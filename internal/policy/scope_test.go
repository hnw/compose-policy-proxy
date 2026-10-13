package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
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
