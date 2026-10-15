package policy

import (
	"encoding/json"
	"maps"
	"regexp"
	"slices"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// A list request has to prove on its own that it cannot observe outside the project,
// because it addresses no resource whose ownership could be checked.

// The resource kinds a list request can be scoped to. They name the resource type
// in the denial message.
const (
	kindContainer = "container"
	kindNetwork   = "network"
	kindVolume    = "volume"
)

// checkListScope decides whether a list request proves it cannot observe outside
// the project, through a project label filter or a name filter of declared names.
func (p *Policy) checkListScope(kind, filters string) (string, error) {
	names := p.declaredNames(kind)

	if filters == "" {
		return "", denyf("", "",
			"list request carries no filters, so it would observe every %s", kind)
	}
	var byKey map[string]json.RawMessage
	if err := json.Unmarshal([]byte(filters), &byKey); err != nil {
		return "", denyf("", "", "list filters cannot be decoded: %v", err)
	}
	if len(byKey) == 0 {
		return "", denyf("", "",
			"list request carries empty filters, so it would observe every %s", kind)
	}

	want := LabelProject + "=" + p.project.Name
	var nameValues []string
	byLabel, byName := false, false
	for key, rawValues := range byKey {
		values, err := decodeFilterValues(key, rawValues)
		if err != nil {
			return "", err
		}
		switch key {
		case "label":
			// Docker ANDs the patterns inside one filter key, in both the object
			// and the array form, which an Engine OR would turn into a wider set.
			if slices.Contains(values, want) {
				byLabel = true
			}
		case "name":
			// A network or volume may also be pinned by name, which is how
			// Compose looks one up. Every value has to be a declared name.
			if len(names) == 0 {
				continue
			}
			for _, v := range values {
				if !slices.Contains(names, v) {
					return "", denyf("", "",
						"%s list filter names %q, which project %q does not declare", kind, v, p.project.Name)
				}
			}
			if len(values) > 0 {
				byName, nameValues = true, values
			}
		}
	}

	switch {
	case byLabel:
		// The label filter already bounds the result, so every other key is
		// forwarded as sent, since the Engine ANDs the keys of one request.
		return "", nil
	case byName:
		return pinNameFilter(byKey, nameValues)
	default:
		return "", denyf("", "",
			"list request must filter on %s=%s or on a declared name, so that it cannot observe other projects",
			LabelProject, p.project.Name)
	}
}

// pinNameFilter anchors the name filter the client sent, because the Engine matches
// it unanchored. QuoteMeta keeps a name that is itself a regex, such as my.volume, literal.
func pinNameFilter(byKey map[string]json.RawMessage, values []string) (string, error) {
	anchored := make([]string, len(values))
	for i, v := range values {
		anchored[i] = "^" + regexp.QuoteMeta(v) + "$"
	}
	name, err := json.Marshal(anchored)
	if err != nil {
		return "", denyf("", "", "name filter cannot be re-encoded: %v", err)
	}
	pinned := make(map[string]json.RawMessage, len(byKey))
	for key, raw := range byKey {
		pinned[key] = raw
	}
	pinned["name"] = name

	out, err := json.Marshal(pinned)
	if err != nil {
		return "", denyf("", "", "list filters cannot be re-encoded: %v", err)
	}
	return string(out), nil
}

// declaredNames are the Docker names a list of this kind may be filtered by.
// Containers are scoped by label, as Compose gives them no comparable name.
func (p *Policy) declaredNames(kind string) []string {
	switch kind {
	case kindNetwork:
		return resolvedNames(compose.NetworkNames(p.project))
	case kindVolume:
		return resolvedNames(compose.VolumeNames(p.project))
	}
	return nil
}

// decodeFilterValues accepts the two filter encodings Docker supports, an object
// of name to boolean and an array of names.
func decodeFilterValues(key string, raw json.RawMessage) ([]string, error) {
	var asObject map[string]bool
	if err := json.Unmarshal(raw, &asObject); err == nil {
		var out []string
		for name, enabled := range asObject {
			if enabled {
				out = append(out, name)
			}
		}
		return out, nil
	}
	var asArray []string
	if err := json.Unmarshal(raw, &asArray); err == nil {
		return asArray, nil
	}
	return nil, denyf("", "", "filter %q is neither an object nor an array", key)
}

// resolvedNames turns a map of Compose keys to resolved Docker names into the
// set of names a list request may be filtered by.
func resolvedNames(m map[string]string) []string {
	return slices.Sorted(maps.Values(m))
}
