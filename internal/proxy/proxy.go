// Package proxy identifies each request on the restricted Docker socket, asks
// policy whether it is authorized, and forwards what policy allows. See docs/policy.md.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	"github.com/hnw/compose-policy-proxy/internal/policy"
)

type Config struct {
	Policy     *policy.Policy
	DockerHost string
	Logger     *slog.Logger
}

type Proxy struct {
	policy   *policy.Policy
	logger   *slog.Logger
	upstream *http.Client
	dialer   dialer
}

// New builds a Proxy and never fails. Everything a request is decided against is
// resolved when the policy is built, and the socket is opened separately.
func New(cfg Config) *Proxy {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", cfg.DockerHost)
	}
	return &Proxy{
		policy: cfg.Policy,
		logger: logger,
		// A redirect would be sent as a fresh request, which the policy never authorized.
		upstream: &http.Client{
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dial(ctx)
			}},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dialer: dial,
	}
}

// ServeHTTP authorizes the request, then forwards it with the path, headers and
// body untouched. The only query it replaces is the list filter the policy pinned.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		p.deny(w, r, policy.Decision{}, err)
		return
	}

	decision, err := p.policy.Authorize(r.Context(), &policy.Request{
		Method: r.Method,
		URL:    r.URL,
		Body:   body,
	})
	if err != nil {
		p.deny(w, r, decision, err)
		return
	}

	query := r.URL.RawQuery
	if decision.Filters != "" {
		query, err = pinFilters(query, decision.Filters)
		if err != nil {
			p.deny(w, r, decision, policy.Malformed("request query cannot be parsed: %v", err))
			return
		}
	}

	// The decision is recorded before forwarding rather than after, so that a
	// stream that outlives the request still leaves an audit trail.
	event{
		Allowed:  true,
		Method:   r.Method,
		Endpoint: decision.Endpoint,
		Target:   decision.Target,
		Service:  decision.Service,
	}.log(p.logger)

	if isStreamingEndpoint(decision.Endpoint) {
		p.forwardStream(w, r, body)
		return
	}
	p.forward(w, r, body, query, decision.Endpoint)
}

// forward relays the request with the version prefix intact, because the daemon
// validates against the version the client negotiated. The host is a placeholder.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte, query string, endpoint string) {
	outURL := *r.URL
	outURL.Scheme = "http"
	outURL.Host = upstreamHost
	outURL.RawQuery = query
	out := r.Clone(r.Context())
	out.URL = &outURL
	out.Host = ""
	out.RequestURI = ""
	if len(body) == 0 {
		out.Body = http.NoBody
		out.ContentLength = 0
	} else {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
	}
	if endpoint == "/version" {
		// The answer is edited below, so it has to arrive as JSON rather than compressed.
		out.Header.Set("Accept-Encoding", "identity")
	}

	resp, err := p.upstream.Do(out) //nolint:gosec // G704: upstream always uses the configured Unix socket
	if err != nil {
		p.writeError(w, http.StatusBadGateway, "upstream docker daemon is unreachable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// The negotiation endpoints answer for the proxy rather than for the Engine: a client
	// that took the Engine's API version from them would send requests this proxy refuses.
	switch endpoint {
	case "/_ping":
		capVersionHeader(resp.Header)
	case "/version":
		capVersionHeader(resp.Header)
		if err := capVersionBody(resp); err != nil {
			p.writeError(w, http.StatusBadGateway, "upstream docker daemon is unreachable")
			return
		}
	}
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// A wait call holds the body open until the container exits, so the headers are
	// flushed now rather than at the first body byte.
	if err := http.NewResponseController(w).Flush(); err != nil {
		p.logger.Debug("could not flush response headers", "error", err.Error())
	}
	_, _ = io.Copy(w, resp.Body)
}

const upstreamHost = "docker"

// pinFilters replaces the filters query with the one the policy decided on, leaving
// every other parameter alone. An unparseable query is refused rather than rebuilt.
func pinFilters(rawQuery, filters string) (string, error) {
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	query.Set("filters", filters)
	return query.Encode(), nil
}

// deny records the refusal and answers the client. It is the only place a refusal
// is written, so every one is a 403 naming what was wrong plus a single log entry.
func (p *Proxy) deny(w http.ResponseWriter, r *http.Request, decision policy.Decision, err error) {
	ev := event{
		Method:   r.Method,
		Endpoint: decision.Endpoint,
		Target:   decision.Target,
	}
	if pe, ok := policy.Inspect(err); ok {
		ev.Field = pe.Field
		ev.Detail = pe.Detail
		ev.Service = pe.Service
	} else {
		ev.Detail = err.Error()
	}
	ev.log(p.logger)

	// The client is told which field was wrong, because "denied" alone is not actionable.
	message := ev.Detail
	if pe, ok := policy.Inspect(err); ok && pe.Field != "" {
		message = pe.Field + ": " + pe.Detail
	}
	p.writeError(w, http.StatusForbidden, message)
}

func (p *Proxy) writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("compose-policy-proxy: %s", message),
	})
}

// readBody buffers the body so policy can decide on it and the same bytes are
// forwarded. A body over policy.MaxBodySize is refused rather than partially compared.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(r.Body, policy.MaxBodySize+1))
	if err != nil {
		return nil, policy.Malformed("request body cannot be read")
	}
	if len(body) > policy.MaxBodySize {
		return nil, policy.Malformed("request body exceeds %d bytes", policy.MaxBodySize)
	}
	return body, nil
}
