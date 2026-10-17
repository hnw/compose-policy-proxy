package policy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
)

// scopedProject declares the networks and volumes a name filter may name.
func scopedProject() *types.Project {
	return &types.Project{
		Name: projectName,
		Networks: types.Networks{
			"default":  {Name: "demo_default"},
			"frontend": {Name: "demo_frontend"},
			"shared":   {Name: "shared-net", External: true},
			"dotted":   {Name: "demo.frontend", External: true},
		},
		Volumes: types.Volumes{"cache": {Name: "demo_cache"}},
	}
}

func TestScopeFilters(t *testing.T) {
	p := &Policy{project: scopedProject()}
	allowed := []string{
		`{"label":{"com.docker.compose.project=demo":true}}`,
		// Docker ANDs the patterns inside one filter key, so Compose's own
		// filter is narrow enough.
		`{"label":{"com.docker.compose.project=demo":true,"com.docker.compose.config-hash":true}}`,
		`{"label":["com.docker.compose.project=demo"]}`,
		`{"label":{"com.docker.compose.project=demo":true},"status":["running"]}`,
	}
	for _, f := range allowed {
		pinned, err := p.checkListScope(kindContainer, f)
		if err != nil {
			t.Errorf("filters %q should be accepted, got %v", f, err)
		}
		if pinned != "" {
			t.Errorf("a container list is scoped by label, so its filters should be forwarded as sent, got %q", pinned)
		}
	}

	denied := []struct {
		filter string
		why    string
	}{
		{"", "no filters at all"},
		{`{}`, "empty filters"},
		{`{"status":["running"]}`, "no project label"},
		{`{"label":{"com.docker.compose.config-hash":true}}`, "another label instead of the project"},
		{`{"label":{"public=yes":true}}`, "an OR that would widen the scope"},
		{`{"label":["public=yes","other=1"]}`, "an OR list without the project"},
		{"not json", "undecodable filters"},
	}
	for _, tc := range denied {
		if _, err := p.checkListScope(kindContainer, tc.filter); err == nil {
			t.Errorf("filters %q should be denied (%s)", tc.filter, tc.why)
		}
	}
}

// TestNamedResourceScope covers name filtering, including the external networks
// Compose looks up by name.
func TestNamedResourceScope(t *testing.T) {
	p := &Policy{project: scopedProject()}

	for _, name := range []string{"demo_default", "demo_frontend", "shared-net"} {
		filter := fmt.Sprintf(`{"name":{%q:true}}`, name)
		pinned, err := p.checkListScope(kindNetwork, filter)
		if err != nil {
			t.Errorf("filtering by the declared network %q should be accepted, got %v", name, err)
		}
		assertPinnedName(t, name, pinned)
	}
	pinned, err := p.checkListScope(kindVolume, `{"name":{"demo_cache":true}}`)
	if err != nil {
		t.Errorf("filtering by a declared volume should be accepted, got %v", err)
	}
	assertPinnedName(t, "demo_cache", pinned)

	// A name that is itself a regular expression is pinned to a literal, or the
	// dot would match any character.
	dotted, err := p.checkListScope(kindNetwork, `{"name":{"demo.frontend":true}}`)
	if err != nil {
		t.Errorf("filtering by the declared network should be accepted, got %v", err)
	}
	assertPinnedName(t, "demo.frontend", dotted)
	if engineNameMatch(onlyNamePattern(t, dotted), "demoXfrontend") {
		t.Error(`the pinned filter for "demo.frontend" also matches "demoXfrontend": the "." was not escaped`)
	}

	pinned, err = p.checkListScope(kindNetwork, `{"label":{"com.docker.compose.project=demo":true}}`)
	if err != nil {
		t.Errorf("a project label filter should be accepted, got %v", err)
	}
	if pinned != "" {
		t.Errorf("a label filter already scopes the result, so the filters should be forwarded as sent, got %q", pinned)
	}

	for _, f := range []string{
		`{"name":{"someone_elses_net":true}}`,
		`{"name":{"demo_frontend":true,"someone_elses_net":true}}`,
		`{"name":{"demo_cache":true}}`,
		`{"name":{"demo.*":true}}`,
		`{"label":{"public=yes":true}}`,
	} {
		if _, err := p.checkListScope(kindNetwork, f); err == nil {
			t.Errorf("filters %q should be denied", f)
		}
	}
}

// The event watch beside a followed log stream observes events, which name other
// projects' activity unless the filters say otherwise. Each key the proxy decides on
// must name exactly the authorized value, and only those values are forwarded.
func TestEventScopeIsPinnedToTheProject(t *testing.T) {
	project := scopedProject()
	const (
		projectLabel = `"label":{"com.docker.compose.project=demo":true}`
		container    = `"type":{"container":true}`
	)
	allowed := []struct {
		filters string
		why     string
	}{
		{"{" + projectLabel + "," + container + "}", "exactly the authorized conditions"},
		{`{"label":["com.docker.compose.project=demo"],"type":["container"]}`, "the array form of both keys"},
		{"{" + projectLabel + "," + container + `,"container":"abc"}`, "one more container of the project"},
	}
	for _, tc := range allowed {
		t.Run(tc.why, func(t *testing.T) {
			pinned, err := checkEventScope(project, tc.filters)
			if err != nil {
				t.Fatalf("filters %q should be accepted, got %v", tc.filters, err)
			}
			want := `{"label":["com.docker.compose.project=demo"],"type":["container"]}`
			if pinned != want {
				t.Errorf("forwarded filters = %q, want %q", pinned, want)
			}
		})
	}

	denied := []struct {
		filters string
		why     string
	}{
		{"", "no filters at all"},
		{"{}", "empty filters"},
		{"not json", "undecodable filters"},
		{"{" + container + "}", "no project label"},
		{"{" + projectLabel + "}", "no event type"},
		{`{"label":{"com.docker.compose.project=someone-else":true},"type":{"container":true}}`, "another project"},
		{`{"label":{"com.docker.compose.project=demo":true,"com.docker.compose.project=someone-else":true},` +
			`"type":{"container":true}}`, "two projects"},
		{`{"label":["com.docker.compose.project=demo","com.docker.compose.service=app"],"type":{"container":true}}`,
			"a second value beside the project label"},
		{`{"label":{"com.docker.compose.project=demo":true},"type":{"image":true}}`, "another event type"},
		{`{"label":{"com.docker.compose.project=demo":true},"type":{"container":true,"image":true}}`,
			"container events and more"},
	}
	for _, tc := range denied {
		t.Run(tc.why, func(t *testing.T) {
			if pinned, err := checkEventScope(project, tc.filters); err == nil {
				t.Errorf("filters %q should be denied (%s), forwarded %q", tc.filters, tc.why, pinned)
			}
		})
	}
}

// The event watch exists to keep a followed log stream open, so `logs` authorizes it and
// no other command does.
func TestEventStreamNeedsTheLogsCommand(t *testing.T) {
	project, _, _ := fixture()
	filters := `{"label":{"com.docker.compose.project=` + project.Name + `":true},"type":{"container":true}}`

	for _, tc := range []struct {
		name     string
		commands Commands
		want     bool
	}{
		{"logs", Commands{commandLogs}, true},
		{"every command", DefaultCommands(), true},
		{"run", Commands{commandRun}, false},
		{"start,stop,restart,pull", Commands{commandStart, commandStop, commandRestart, commandPull}, false},
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
			path := "/v1.51/events?filters=" + url.QueryEscape(filters)
			decision, err := p.Authorize(t.Context(), request(t, "GET", path))
			if tc.want {
				if err != nil {
					t.Fatalf("the event watch with %v must be allowed, got %v", tc.commands, err)
				}
				if decision.Endpoint != "/events" {
					t.Fatalf("endpoint = %q, want /events", decision.Endpoint)
				}
				return
			}
			pe, ok := Inspect(err)
			if !ok {
				t.Fatalf("the event watch with %v must be refused, got %v", tc.commands, err)
			}
			if want := "compose logs is not available"; !strings.Contains(pe.Detail, want) {
				t.Errorf("the refusal names %q, got %q", want, pe.Detail)
			}
		})
	}
}

// assertPinnedName checks that the forwarded filter matches the declared name and
// nothing else. The bare name Compose sends would also match "demo_frontend_other".
func assertPinnedName(t *testing.T, name, pinned string) {
	t.Helper()
	pattern := onlyNamePattern(t, pinned)
	if !engineNameMatch(pattern, name) {
		t.Errorf("pinned filter %q does not match the declared name %q", pattern, name)
	}
	for _, other := range []string{name + "_other", "x" + name, name + "2"} {
		if engineNameMatch(pattern, other) {
			t.Errorf("pinned filter %q for %q also matches %q", pattern, name, other)
		}
	}
}

func onlyNamePattern(t *testing.T, pinned string) string {
	t.Helper()
	var byKey map[string][]string
	if err := json.Unmarshal([]byte(pinned), &byKey); err != nil {
		t.Fatalf("pinned filters %q cannot be decoded: %v", pinned, err)
	}
	if len(byKey["name"]) != 1 {
		t.Fatalf("pinned filters %q should carry exactly one name, got %v", pinned, byKey["name"])
	}
	return byKey["name"][0]
}

// engineNameMatch applies a name filter as an unanchored regex over the name.
func engineNameMatch(pattern, name string) bool {
	return regexp.MustCompile(pattern).MatchString(name)
}
