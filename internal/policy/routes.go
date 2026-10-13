package policy

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// allowlist is the complete set of Docker API operations the proxy forwards, with
// the methods allowed on each. docs/policy.md lists them and what is left out.
var allowlist = map[string][]string{
	// API negotiation. No resource addressed.
	"/_ping":   {"GET", "HEAD"},
	"/version": {"GET"},
	"/info":    {"GET"},

	// Containers. Create, list, inspect, and the lifecycle operations a one-off
	// run performs. Every {id} route requires ownership.
	"/containers/create":      {"POST"},
	"/containers/json":        {"GET"},
	"/containers/{id}":        {"DELETE", "GET"},
	"/containers/{id}/json":   {"GET"},
	"/containers/{id}/attach": {"POST"},
	"/containers/{id}/start":  {"POST"},
	"/containers/{id}/wait":   {"POST"},
	"/containers/{id}/stop":   {"POST"},
	"/containers/{id}/kill":   {"POST"},
	"/containers/{id}/resize": {"POST"},

	// Images. Inspect and pull, both restricted to an image the project declares.
	"/images/create":      {"POST"},
	"/images/{name}/json": {"GET"},

	// Networks. Inspect and list, scoped to declared networks, plus create.
	"/networks":        {"GET"},
	"/networks/{id}":   {"GET"},
	"/networks/create": {"POST"},

	// Volumes. Inspect and list, scoped to declared volumes, plus create.
	"/volumes":        {"GET"},
	"/volumes/{name}": {"GET"},
	"/volumes/create": {"POST"},
}

// maxAPIVersion is the newest Docker API version this proxy interprets. A newer one
// is refused, because it may carry fields the policy does not classify.
const maxAPIVersion = "1.51"

// minAPIVersion stops a nonsense version from reaching routing logic. The Engine
// sets the real minimum.
const minAPIVersion = "1.24"

// CapAPIVersion returns the version a client may negotiate, which is the older of the
// Engine's version and the one this proxy validates. An empty result means the Engine's
// version could not be read, and the caller must keep the Engine's own value.
func CapAPIVersion(engineVersion string) string {
	cmp, err := compareVersion(engineVersion, maxAPIVersion)
	if err != nil {
		return ""
	}
	if cmp > 0 {
		return maxAPIVersion
	}
	return engineVersion
}

// CheckEngineAPIVersion reports whether the Engine and the proxy share a version at all:
// the Engine's oldest must not exceed the proxy's newest, and the Engine's newest must
// not fall below the proxy's oldest.
func CheckEngineAPIVersion(engineMin, engineMax string) error {
	if oldest, err := compareVersion(engineMin, maxAPIVersion); err != nil || oldest > 0 {
		return fmt.Errorf("docker engine requires API version %q or newer, which the %q this proxy validates cannot serve; upgrade the proxy",
			engineMin, maxAPIVersion)
	}
	if newest, err := compareVersion(engineMax, minAPIVersion); err != nil || newest < 0 {
		return fmt.Errorf("docker engine serves up to API version %q, older than the %q this proxy needs; upgrade the engine",
			engineMax, minAPIVersion)
	}
	return nil
}

// operation is a request path resolved against the allowlist. It is returned
// even when the request is refused, so a denial can name what it was about.
type operation struct {
	// Endpoint is the allowlist key, without the version prefix.
	Endpoint string
	// Version is the negotiated API version, or "" when the path had no prefix.
	Version string
	Target  string
}

// resolve maps a request path onto the allowlist, separating the version prefix here
// and only here so the caller's path stays what gets forwarded.
func resolve(path string) (operation, error) {
	version, rest := splitVersion(path)

	if _, ok := allowlist[rest]; ok {
		return operation{Endpoint: rest, Version: version}, nil
	}

	// Nothing matched literally, so try the shape of a resource endpoint. Only the
	// second position is substituted, and only if the result is itself allowlisted.
	segments := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
		return operation{}, denyf("", "", "docker API path %q is not allowed", rest)
	}
	suffix := ""
	if len(segments) > 2 {
		suffix = "/" + strings.Join(segments[2:], "/")
	}
	for _, placeholder := range []string{"{id}", "{name}"} {
		pattern := "/" + segments[0] + "/" + placeholder + suffix
		if _, ok := allowlist[pattern]; ok {
			// An allowlisted pattern reached this way names its resource in the
			// position that was substituted, so that position is the target.
			return operation{Endpoint: pattern, Version: version, Target: segments[1]}, nil
		}
	}
	return operation{}, denyf("", "",
		"docker API endpoint %q is not allowed; this proxy implements only docker compose run", rest)
}

func splitVersion(path string) (version, rest string) {
	trimmed := strings.TrimPrefix(path, "/")
	first, remainder, found := strings.Cut(trimmed, "/")
	if !found || !isVersion(first) {
		return "", path
	}
	return first, "/" + remainder
}

func isVersion(s string) bool {
	_, _, err := splitMinor(s)
	return err == nil
}

func (o operation) checkVersion() error {
	if o.Version == "" {
		return nil
	}
	cmp, err := compareVersion(o.Version, maxAPIVersion)
	if err != nil {
		return denyf("", "", "docker API version %q is not understood", o.Version)
	}
	if cmp > 0 {
		return denyf("", "",
			"docker API version %q is newer than the %q this proxy validates; the proxy must be upgraded",
			o.Version, maxAPIVersion)
	}
	if cmp, err := compareVersion(o.Version, minAPIVersion); err == nil && cmp < 0 {
		return denyf("", "",
			"docker API version %q is older than the supported minimum %q", o.Version, minAPIVersion)
	}
	return nil
}

func (o operation) checkMethod(method string) error {
	if slices.Contains(allowlist[o.Endpoint], method) {
		return nil
	}
	return denyf("", "", "method %s is not allowed on %s", method, o.Endpoint)
}

func compareVersion(a, b string) (int, error) {
	aMajor, aMinor, err := splitMinor(a)
	if err != nil {
		return 0, err
	}
	bMajor, bMinor, err := splitMinor(b)
	if err != nil {
		return 0, err
	}
	if aMajor != bMajor {
		return cmp.Compare(aMajor, bMajor), nil
	}
	return cmp.Compare(aMinor, bMinor), nil
}

func splitMinor(v string) (major, minor int, err error) {
	body := strings.TrimPrefix(v, "v")
	majorStr, minorStr, ok := strings.Cut(body, ".")
	if !ok {
		return 0, 0, fmt.Errorf("malformed API version %q", v)
	}
	if major, err = strconv.Atoi(majorStr); err != nil {
		return 0, 0, err
	}
	if minor, err = strconv.Atoi(minorStr); err != nil {
		return 0, 0, err
	}
	return major, minor, nil
}

// readOnlyOperations are the only container operations allowed on a protected
// service. What counts is the effect on the container, not the HTTP method.
var readOnlyOperations = map[string]bool{
	"/containers/json GET":       true, // listing observes
	"/containers/{id} GET":       true, // reading container state observes
	"/containers/{id}/json GET":  true, // inspect observes
	"/containers/{id}/wait POST": true, // waiting changes nothing
}

func isReadOnlyOperation(endpoint, method string) bool {
	return readOnlyOperations[endpoint+" "+method]
}

// allowlistEndpoints returns every allowlisted path, for documentation and for
// the test that asserts the list stays minimal.
func allowlistEndpoints() []string {
	return slices.Collect(maps.Keys(allowlist))
}
