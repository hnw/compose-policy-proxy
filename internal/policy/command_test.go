package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
)

func TestParseCommands(t *testing.T) {
	cases := []struct {
		list string
		want Commands
	}{
		{"", nil},
		{"run,start,stop", Commands{"run", "start", "stop"}},
		{"run", Commands{"run"}},
		{"start,stop", Commands{"start", "stop"}},
		{" restart , pull , logs ", Commands{"logs", "pull", "restart"}},
		{"run,run,start", Commands{"run", "start"}},
		{"run,", Commands{"run"}},
		{"run,start,stop,restart,pull,logs", Commands{"logs", "pull", "restart", "run", "start", "stop"}},
	}
	for _, tc := range cases {
		t.Run("["+tc.list+"]", func(t *testing.T) {
			got, err := ParseCommands(tc.list)
			if err != nil {
				t.Fatalf("%q was refused: %v", tc.list, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ParseCommands(%q) = %v, want %v", tc.list, got, tc.want)
			}
		})
	}

	// A name the policy has no rule for is an error, so a typo cannot look like a
	// narrower setting than it is.
	for _, list := range []string{"up", "run,down", "logs,up", "log", "RUN", "run start"} {
		t.Run(list, func(t *testing.T) {
			if _, err := ParseCommands(list); err == nil {
				t.Errorf("%q was accepted, but no command answers to it", list)
			} else if !strings.Contains(err.Error(), "--allow-command") {
				t.Errorf("refusal = %q, want it to name the setting", err)
			}
		})
	}
}

func TestControlFollowsTheAllowedCommands(t *testing.T) {
	operations := []struct {
		name   string
		oneoff bool
		method string
		path   string
		// command authorizes the operation; empty means no command does, because the
		// operation only observes
		command string
	}{
		{name: "kill a one-off container", oneoff: true, method: "POST", path: "/kill", command: commandRun},
		{name: "start a service container", method: "POST", path: "/start", command: commandStart},
		{name: "stop a service container", method: "POST", path: "/stop", command: commandStop},
		{name: "restart a service container", method: "POST", path: "/restart?t=5", command: commandRestart},
		{name: "restart a one-off container", oneoff: true, method: "POST", path: "/restart?t=5", command: commandRun},
		{name: "read the logs of a service container", method: "GET", path: "/logs?stdout=1&stderr=1", command: commandLogs},
		{name: "read the logs of a one-off container", oneoff: true, method: "GET", path: "/logs?follow=1", command: commandLogs},
		{name: "read a service container", method: "GET", path: "/json"},
	}
	cases := []struct {
		name     string
		commands Commands
	}{
		{"omitted", DefaultCommands()},
		{"run", Commands{commandRun}},
		{"start,stop", Commands{commandStart, commandStop}},
		{"start", Commands{commandStart}},
		{"stop", Commands{commandStop}},
		{"restart", Commands{commandRestart}},
		{"logs", Commands{commandLogs}},
		{"start,stop,restart,logs", Commands{commandStart, commandStop, commandRestart, commandLogs}},
		{"empty", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, op := range operations {
				t.Run(op.name, func(t *testing.T) {
					project, _, insp := inspectFixture()
					if !op.oneoff {
						insp.Config.Labels[LabelOneoff] = "False"
					}
					p := policyFor(&project, insp, tc.commands)
					_, err := p.Authorize(t.Context(),
						request(t, op.method, "/v1.51/containers/"+containerID+op.path))
					if op.command == "" || slices.Contains(tc.commands, op.command) {
						if err != nil {
							t.Fatalf("%s %s must be allowed, got %v", op.method, op.path, err)
						}
						return
					}
					pe, ok := Inspect(err)
					if !ok {
						t.Fatalf("%s %s must be refused for %v, got %v",
							op.method, op.path, tc.commands, err)
					}
					if want := "compose " + op.command + " is not available"; !strings.Contains(pe.Detail, want) {
						t.Errorf("%s %s was refused for %q, want a refusal naming %q",
							op.method, op.path, pe.Detail, want)
					}
				})
			}
		})
	}
}

func TestRunOnlyOperationsFollowTheRunCommand(t *testing.T) {
	project, service, create := fixture()
	project.Services = types.Services{"app": service}
	create.Config.Labels = map[string]string{
		LabelProject: project.Name, LabelService: service.Name, LabelOneoff: oneoffLabelValue,
	}
	body, err := json.Marshal(create)
	if err != nil {
		t.Fatalf("encode create request: %v", err)
	}

	operations := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "one-off create", method: "POST", path: "/v1.51/containers/create", body: string(body)},
		{name: "network create", method: "POST", path: "/v1.51/networks/create", body: `{"Name":"demo_frontend",` +
			`"Labels":{"com.docker.compose.project":"demo","com.docker.compose.network":"frontend"}}`},
		{name: "volume create", method: "POST", path: "/v1.51/volumes/create", body: `{"Name":"demo_cache",` +
			`"Labels":{"com.docker.compose.project":"demo","com.docker.compose.volume":"cache"}}`},
	}
	cases := []struct {
		name     string
		commands Commands
		want     bool
	}{
		{"omitted", DefaultCommands(), true},
		{"run", Commands{commandRun}, true},
		{"start,stop", Commands{commandStart, commandStop}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		p, err := New(Config{
			Project:         project,
			DockerHost:      hostSocket,
			Listen:          proxySocket,
			Engine:          stubInspector{},
			AllowedCommands: tc.commands,
		})
		if err != nil {
			t.Fatalf("build policy: %v", err)
		}
		for _, op := range operations {
			t.Run(tc.name+"/"+op.name, func(t *testing.T) {
				req := request(t, op.method, op.path)
				req.Body = []byte(op.body)
				_, err := p.Authorize(t.Context(), req)
				if tc.want != (err == nil) {
					t.Fatalf("%s %s with %v: err = %v, want allowed = %t",
						op.method, op.path, tc.commands, err, tc.want)
				}
			})
		}
	}
}

// A pull is what `docker compose pull` performs, and what `run` needs before it can
// create anything, so either command authorizes it and no other does. Which references
// may be pulled is authorizePull's decision, tested with it.
func TestPullFollowsTheRunAndPullCommands(t *testing.T) {
	project, service, _ := fixture()
	project.Services = types.Services{"app": service}

	for _, tc := range []struct {
		name     string
		commands Commands
		want     bool
	}{
		{"omitted", DefaultCommands(), true},
		{"run", Commands{commandRun}, true},
		{"pull", Commands{commandPull}, true},
		{"start,stop", Commands{commandStart, commandStop}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(Config{
				Project:         project,
				DockerHost:      hostSocket,
				Listen:          proxySocket,
				Engine:          stubInspector{},
				AllowedCommands: tc.commands,
			})
			if err != nil {
				t.Fatalf("build policy: %v", err)
			}
			_, err = p.Authorize(t.Context(),
				request(t, "POST", "/v1.51/images/create?fromImage=alpine:3.20"))
			if tc.want != (err == nil) {
				t.Fatalf("a pull with %v: err = %v, want allowed = %t", tc.commands, err, tc.want)
			}
		})
	}
}
