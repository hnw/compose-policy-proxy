package policy

import (
	"errors"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
)

func TestResolveAllowlistedEndpoints(t *testing.T) {
	cases := []struct {
		path     string
		endpoint string
		version  string
		target   string
	}{
		{"/_ping", "/_ping", "", ""},
		{"/v1.51/version", "/version", "v1.51", ""},
		{"/v1.51/containers/create", "/containers/create", "v1.51", ""},
		{"/v1.51/containers/json", "/containers/json", "v1.51", ""},
		{"/v1.51/containers/abc/json", "/containers/{id}/json", "v1.51", "abc"},
		{"/v1.51/containers/abc/attach", "/containers/{id}/attach", "v1.51", "abc"},
		{"/v1.51/containers/abc/start", "/containers/{id}/start", "v1.51", "abc"},
		{"/v1.51/containers/abc/wait", "/containers/{id}/wait", "v1.51", "abc"},
		{"/v1.51/containers/abc/stop", "/containers/{id}/stop", "v1.51", "abc"},
		{"/v1.51/containers/abc/kill", "/containers/{id}/kill", "v1.51", "abc"},
		{"/v1.51/containers/abc/resize", "/containers/{id}/resize", "v1.51", "abc"},
		{"/v1.51/containers/abc", "/containers/{id}", "v1.51", "abc"},
		{"/v1.51/images/alpine:3.20/json", "/images/{name}/json", "v1.51", "alpine:3.20"},
		{"/v1.51/images/alpine/json", "/images/{name}/json", "v1.51", "alpine"},
		{"/v1.51/images/create", "/images/create", "v1.51", ""},
		{"/v1.51/networks", "/networks", "v1.51", ""},
		{"/v1.51/networks/demo_frontend", "/networks/{id}", "v1.51", "demo_frontend"},
		{"/v1.51/networks/create", "/networks/create", "v1.51", ""},
		{"/v1.51/volumes", "/volumes", "v1.51", ""},
		{"/v1.51/volumes/demo_cache", "/volumes/{name}", "v1.51", "demo_cache"},
		{"/v1.51/volumes/create", "/volumes/create", "v1.51", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			op, err := resolve(tc.path)
			if err != nil {
				t.Fatalf("expected the path to resolve, got %v", err)
			}
			if op.Endpoint != tc.endpoint {
				t.Errorf("endpoint = %q, want %q", op.Endpoint, tc.endpoint)
			}
			if op.Version != tc.version {
				t.Errorf("version = %q, want %q", op.Version, tc.version)
			}
			if op.Target != tc.target {
				t.Errorf("target = %q, want %q", op.Target, tc.target)
			}
		})
	}
}

func TestResolveRejectsEverythingElse(t *testing.T) {
	// Anything a Docker client can ask for but the end-to-end tests never
	// exercised has to be refused, since the allowlist is deny by default.
	denied := []string{
		"/v1.51/containers/abc/exec",
		"/v1.51/containers/abc/copy",
		"/v1.51/containers/abc/rename",
		"/v1.51/containers/abc/update",
		"/v1.51/containers/abc/archive",
		"/v1.51/containers/abc/logs",
		"/v1.51/build",
		"/v1.51/images/prune",
		"/v1.51/images/alpine/tag",
		"/v1.51/networks/demo/disconnect",
		"/v1.51/networks/demo/connect",
		"/v1.51/events",
		"/v1.51/services",
		"/v1.51/swarm/join",
		"/v1.51/plugins/pull",
		"/v1.51/secrets",
		"/v1.51/configs",
		"/v1.51/system/df",
		"/v1.51/distribution/alpine/json",
		"/",
		"/v1.51",
		"/v1.51/",
		"/v1.51/containers",
	}
	for _, path := range denied {
		t.Run(path, func(t *testing.T) {
			if op, err := resolve(path); err == nil {
				t.Fatalf("path %q resolved to %q but should be denied", path, op.Endpoint)
			}
		})
	}
}

func TestCheckVersion(t *testing.T) {
	allowed := []string{"", "v1.24", "v1.40", "v1.51"}
	for _, v := range allowed {
		if err := (operation{Endpoint: "/version", Version: v}).checkVersion(); err != nil {
			t.Errorf("version %q should be accepted, got %v", v, err)
		}
	}
	// A newer or nonsensical version is refused, since the proxy would not know
	// which fields the request may carry.
	for _, v := range []string{"v1.52", "v2.0", "v9.99", "vnope", "v1.x"} {
		if err := (operation{Endpoint: "/version", Version: v}).checkVersion(); err == nil {
			t.Errorf("version %q should be refused", v)
		}
	}
}

func TestCheckMethod(t *testing.T) {
	cases := []struct {
		endpoint string
		method   string
		allowed  bool
	}{
		{"/containers/create", "POST", true},
		{"/containers/create", "GET", false},
		{"/containers/{id}", "DELETE", true},
		{"/containers/{id}", "GET", true},
		{"/containers/{id}", "POST", false},
		{"/images/{name}/json", "GET", true},
		{"/images/{name}/json", "DELETE", false},
		{"/_ping", "HEAD", true},
		{"/_ping", "POST", false},
	}
	for _, tc := range cases {
		err := operation{Endpoint: tc.endpoint}.checkMethod(tc.method)
		if tc.allowed && err != nil {
			t.Errorf("%s %s should be allowed, got %v", tc.method, tc.endpoint, err)
		}
		if !tc.allowed && err == nil {
			t.Errorf("%s %s should be denied", tc.method, tc.endpoint)
		}
	}
}

// TestRefusalNamesTheOperationItWasAbout checks that a refusal still arrives with
// the endpoint and target it was decided about. An empty Policy settles all of it.
func TestRefusalNamesTheOperationItWasAbout(t *testing.T) {
	p := &Policy{}

	decision, err := p.Authorize(t.Context(), request(t, "POST", "/v1.51/containers/abc/exec"))
	if err == nil {
		t.Fatal("exec was allowed")
	}
	if decision.Endpoint != "" || decision.Target != "" {
		t.Errorf("an endpoint that never matched should resolve to nothing, got %+v", decision)
	}
	if pe, ok := Inspect(err); !ok || !strings.Contains(pe.Detail, "not allowed") {
		t.Errorf("refusal = %v, want one that names the endpoint as not allowed", err)
	}

	decision, err = p.Authorize(t.Context(), request(t, "POST", "/v9.99/containers/abc/start"))
	if err == nil {
		t.Fatal("an unsupported API version was allowed")
	}
	if decision.Endpoint != "/containers/{id}/start" || decision.Target != "abc" {
		t.Errorf("the refused operation was not named: %+v", decision)
	}

	decision, err = p.Authorize(t.Context(), request(t, "PUT", "/v1.51/containers/abc/json"))
	if err == nil {
		t.Fatal("a method the allowlist does not grant was allowed")
	}
	if decision.Endpoint != "/containers/{id}/json" || decision.Target != "abc" {
		t.Errorf("the refused operation was not named: %+v", decision)
	}
	if pe, ok := Inspect(err); !ok || !strings.Contains(pe.Detail, "method PUT is not allowed") {
		t.Errorf("refusal = %v, want one that names the method", err)
	}
}

// TestResourceShapedPathsAreRefusedByOwnership pins that routing is coarse on purpose.
// A two-segment path resolves to the resource endpoint, and ownership refuses the name.
func TestResourceShapedPathsAreRefusedByOwnership(t *testing.T) {
	p := &Policy{project: &types.Project{Name: "demo"}}

	for _, path := range []string{
		"/v1.51/networks/prune",
		"/v1.51/volumes/prune",
		"/v1.51/volumes/someone_elses",
	} {
		op, err := resolve(path)
		if err != nil {
			t.Fatalf("%q did not resolve, so ownership was never reached: %v", path, err)
		}
		if op.Target == "" {
			t.Fatalf("%q resolved to %q without a target", path, op.Endpoint)
		}

		_, err = p.Authorize(t.Context(), request(t, "GET", path))
		if errors.Is(err, errUnhandledEndpoint) {
			t.Errorf("%q was refused for having no rule rather than by ownership", path)
			continue
		}
		pe, ok := Inspect(err)
		if !ok {
			t.Fatalf("%q was allowed, but %q is not declared by the project", path, op.Target)
		}
		if !strings.Contains(pe.Detail, "is not declared by compose project") {
			t.Errorf("%q was refused as %q rather than by ownership", path, pe.Detail)
		}
	}
}

// TestEveryAllowlistedEndpointHasARule pins the fail-closed default from the
// allowlist side, where an endpoint without a decision rule is refused.
func TestEveryAllowlistedEndpointHasARule(t *testing.T) {
	p := &Policy{project: &types.Project{Name: "demo"}, inspect: stubInspector{}}

	for endpoint := range allowlist {
		_, _, err := p.decide(t.Context(), operation{Endpoint: endpoint, Target: "target"}, &Request{URL: &url.URL{}})
		if errors.Is(err, errUnhandledEndpoint) {
			t.Errorf("%s is allowlisted but no authorization rule covers it", endpoint)
		}
	}
}

// TestEndpointWithoutARuleIsRefused pins the same default from the other side,
// where an operation is never authorized by having no rule that mentions it.
func TestEndpointWithoutARuleIsRefused(t *testing.T) {
	p := &Policy{project: &types.Project{Name: "demo"}, inspect: stubInspector{}}

	_, _, err := p.decide(t.Context(), operation{Endpoint: "/events", Target: ""}, &Request{URL: &url.URL{}})
	if !errors.Is(err, errUnhandledEndpoint) {
		t.Fatalf("an endpoint no rule covers was not refused: %v", err)
	}
}

func TestAllowlistIsMinimal(t *testing.T) {
	// The allowlist is the smallest the clients need, confirmed by the end-to-end
	// tests, so this pins it and keeps adding an endpoint a deliberate act.
	want := []string{
		"/_ping",
		"/containers/create",
		"/containers/json",
		"/containers/{id}",
		"/containers/{id}/attach",
		"/containers/{id}/json",
		"/containers/{id}/kill",
		"/containers/{id}/resize",
		"/containers/{id}/start",
		"/containers/{id}/stop",
		"/containers/{id}/wait",
		"/images/create",
		"/images/{name}/json",
		"/info",
		"/networks",
		"/networks/create",
		"/networks/{id}",
		"/version",
		"/volumes",
		"/volumes/create",
		"/volumes/{name}",
	}
	got := allowlistEndpoints()
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("allowlist changed\n got: %v\nwant: %v", got, want)
	}
}

// TestUndescribedContainerOperationIsNotReadOnly pins the fallback. An operation the
// exception list does not name is refused, which makes a new endpoint safe to add.
func TestUndescribedContainerOperationIsNotReadOnly(t *testing.T) {
	for _, key := range []string{
		"/containers/{id}/logs GET",
		"/containers/{id} HEAD",
		"/containers/{id}/attach POST",
		"/containers/{id}/start POST",
		"/containers/{id}/stop POST",
		"/containers/{id}/kill POST",
		"/containers/{id}/resize POST",
		"/containers/{id} DELETE",
		"/containers/create POST",
	} {
		endpoint, method, _ := strings.Cut(key, " ")
		if isReadOnlyOperation(endpoint, method) {
			t.Errorf("%s was treated as read-only", key)
		}
	}
}

// TestReadOnlyOperationsAreAllowlisted keeps the exception list honest. An entry the
// allowlist does not grant is unreachable and reads as a decision about nothing.
func TestReadOnlyOperationsAreAllowlisted(t *testing.T) {
	for key := range readOnlyOperations {
		endpoint, method, _ := strings.Cut(key, " ")
		if !strings.HasPrefix(endpoint, "/containers/") {
			t.Errorf("read-only exception %q is not a container operation", key)
			continue
		}
		granted := false
		for _, allowed := range allowlist[endpoint] {
			if allowed == method {
				granted = true
			}
		}
		if !granted {
			t.Errorf("read-only exception %q is not an allowlisted operation", key)
		}
	}
}
