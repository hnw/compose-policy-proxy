package policy

import (
	"net/url"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/distribution/reference"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// images lists every image reference the project declares.
func images(project *types.Project) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, service := range compose.Services(project) {
		name := compose.ImageName(project, service)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for _, job := range project.AllJobs() {
		if job.Image == "" {
			continue
		}
		if _, ok := seen[job.Image]; ok {
			continue
		}
		seen[job.Image] = struct{}{}
		out = append(out, job.Image)
	}
	return out
}

// imageDeclared reports whether ref matches a declared image,
// normalizing implicit registry, namespace, and tag defaults.
func imageDeclared(project *types.Project, ref string) bool {
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return false
	}
	want := reference.TagNameOnly(named).String()
	for _, declared := range images(project) {
		named, err := reference.ParseNormalizedNamed(declared)
		if err != nil {
			continue
		}
		if reference.TagNameOnly(named).String() == want {
			return true
		}
	}
	return false
}

// authorizePull decides what a POST /images/create request may pull. Registry
// credentials arrive in X-Registry-Auth and are forwarded untouched, never decided on.
func authorizePull(project *types.Project, q url.Values) error {
	if fromSrc := q.Get("fromSrc"); fromSrc != "" {
		return denyf("", "fromImage",
			"compose never pulls from %q; only a declared image reference may be pulled", fromSrc)
	}

	ref := q.Get("fromImage")
	if ref == "" {
		return deny("", "fromImage", "pull request names no image")
	}
	if tag := q.Get("tag"); tag != "" {
		ref += ":" + tag
	}

	pullAll := false
	if v := q.Get("all"); v != "" {
		var err error
		pullAll, err = parseBool(v)
		if err != nil {
			return denyf("", "", "pull parameter all=%q is not a boolean", v)
		}
	}
	return allowPull(project, ref, pullAll)
}

// allowPull reports whether the project permits pulling ref. A bulk pull is
// refused because it would reach beyond what the project declared.
func allowPull(project *types.Project, ref string, pullAll bool) error {
	if pullAll {
		return deny("", "fromImage",
			"compose does not declare a bulk pull target, request asks to pull all images")
	}
	if strings.Contains(ref, ",") {
		return denyf("", "fromImage",
			"compose does not declare a bulk pull target, request asks for %q", ref)
	}
	if !imageDeclared(project, ref) {
		return denyf("", "fromImage",
			"image %q is not declared by compose project %q", ref, project.Name)
	}
	return nil
}
