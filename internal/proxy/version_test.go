package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"testing"

	"github.com/hnw/compose-policy-proxy/internal/policy"
)

func TestServeHTTPCapsTheNegotiatedAPIVersion(t *testing.T) {
	cases := []struct {
		name, method, engine, want string
	}{
		{"an engine newer than the proxy", "GET", "1.54", "1.51"},
		{"an engine older than the proxy", "GET", "1.48", "1.48"},
		{"a head request", "HEAD", "1.54", "1.51"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socket, _ := testProxyWith(t, demoProject(), newDaemon(t, tc.engine),
				slog.NewTextHandler(io.Discard, nil), policy.DefaultCommands())

			resp := do(t, socket, tc.method, "/_ping", "")
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("API-Version"); got != tc.want {
				t.Errorf("API-Version = %q, want %q", got, tc.want)
			}
			if got := resp.Header.Get("Ostype"); got != "linux" {
				t.Errorf("Ostype = %q, want the engine's own value", got)
			}
			if body, _ := io.ReadAll(resp.Body); tc.method == "HEAD" && len(body) != 0 {
				t.Errorf("HEAD returned a body: %q", body)
			}
		})
	}
}

func TestServeHTTPCapsTheVersionAnswer(t *testing.T) {
	cases := []struct {
		name, engine, want string
	}{
		{"an engine newer than the proxy", "1.54", "1.51"},
		{"an engine older than the proxy", "1.48", "1.48"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socket, _ := testProxyWith(t, demoProject(), newDaemon(t, tc.engine),
				slog.NewTextHandler(io.Discard, nil), policy.DefaultCommands())

			resp := do(t, socket, "GET", "/v1.51/version", "")
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			raw, _ := io.ReadAll(resp.Body)
			if resp.ContentLength != int64(len(raw)) {
				t.Errorf("Content-Length = %d, want the %d bytes actually sent",
					resp.ContentLength, len(raw))
			}

			var answer map[string]any
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("the answer is not JSON: %v (%q)", err, raw)
			}
			if answer["ApiVersion"] != tc.want {
				t.Errorf("ApiVersion = %v, want %q", answer["ApiVersion"], tc.want)
			}
			for field, want := range map[string]any{
				"MinAPIVersion":          "1.24",
				"Version":                "29.0.1",
				"FieldANewerEngineAdded": map[string]any{"nested": true},
			} {
				if got := answer[field]; !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %v, want %v", field, got, want)
				}
			}
		})
	}
}
