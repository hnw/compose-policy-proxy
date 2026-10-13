package policy

import (
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// This file holds the only transformations the proxy performs, each applied to a
// single value where it becomes comparable rather than to a whole service or request.

// capabilityName gives a capability its canonical uppercase CAP_ form, so that
// "net_admin", "NET_ADMIN" and "CAP_NET_ADMIN" compare equal.
func capabilityName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "CAP_") {
		s = "CAP_" + s
	}
	return s
}

// canonicalCapabilities deduplicates and sorts a capability list, so order and
// spelling cannot smuggle a difference past the comparison.
func canonicalCapabilities(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, c := range in {
		name := capabilityName(c)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func capabilitiesSubset(sub, super []string) bool {
	set := make(map[string]struct{}, len(super))
	for _, c := range super {
		set[c] = struct{}{}
	}
	for _, c := range sub {
		if _, ok := set[c]; !ok {
			return false
		}
	}
	return true
}

func stringSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return out
}

// normalizedIP canonicalizes a textual address so an alternative spelling or an
// IPv4-mapped IPv6 literal cannot fake a difference. An unparsable address is returned trimmed.
func normalizedIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	if v4 := addr.Unmap(); v4.Is4() {
		return v4.String()
	}
	return addr.String()
}

func sameIP(a, b string) bool {
	return normalizedIP(a) == normalizedIP(b)
}

func cleanPath(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
}

func parseBoolOption(s string) (bool, bool) {
	v, err := strconv.ParseBool(strings.TrimSpace(s))
	return v, err == nil
}

// parseBool reads a Docker API query parameter that carries a boolean.
func parseBool(s string) (bool, error) {
	return strconv.ParseBool(strings.TrimSpace(s))
}

func dedupNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
