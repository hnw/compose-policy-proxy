package proxy

import (
	"io"
	"log/slog"
	"os"
)

type event struct {
	Allowed bool
	// Endpoint has the version prefix and query string removed.
	Method   string
	Endpoint string
	Target   string
	Service  string
	// Field is the Docker field the policy found wrong. It is empty when the
	// refusal names no field, such as a container of another project.
	Field string
	// Detail explains a denial, assembled only from policy decisions and the
	// compared field values. Config.Env and X-Registry-Auth are never compared.
	Detail string
}

func (e event) log(logger *slog.Logger) {
	attrs := []any{
		slog.Bool("allowed", e.Allowed),
		slog.String("method", e.Method),
		slog.String("endpoint", e.Endpoint),
	}
	if e.Target != "" {
		attrs = append(attrs, slog.String("target", e.Target))
	}
	if e.Service != "" {
		attrs = append(attrs, slog.String("service", e.Service))
	}
	if e.Field != "" {
		attrs = append(attrs, slog.String("field", e.Field))
	}
	if e.Detail != "" {
		attrs = append(attrs, slog.String("detail", e.Detail))
	}
	if e.Allowed {
		logger.Info("allowed", attrs...)
		return
	}
	logger.Warn("denied", attrs...)
}

type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

func NewLogger(format LogFormat, level slog.Level) *slog.Logger {
	var w io.Writer = os.Stderr
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	if format == LogFormatJSON {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	return slog.New(handler)
}
