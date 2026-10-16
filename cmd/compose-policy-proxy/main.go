// Command compose-policy-proxy is a Unix socket proxy that confines Docker API
// traffic to what a Compose project allows. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hnw/compose-policy-proxy/internal/compose"
	"github.com/hnw/compose-policy-proxy/internal/engine"
	"github.com/hnw/compose-policy-proxy/internal/policy"
	"github.com/hnw/compose-policy-proxy/internal/proxy"
)

const (
	defaultListen     = "/run/compose-policy-proxy/docker.sock"
	defaultSocketMode = "0660"
	defaultDockerHost = "/var/run/docker.sock"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "compose-policy-proxy:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen       = flag.String("listen", defaultListen, "path of the Unix socket to listen on")
		dockerHost   = flag.String("docker-host", defaultDockerHost, "path of the Docker daemon socket to forward to")
		socketMode   = flag.String("socket-mode", "0660", "file mode of the listening socket, in octal")
		allowCommand = flag.String("allow-command", policy.DefaultCommandList,
			"comma-separated Compose commands to allow: "+policy.DefaultCommandList)
		logFormat   = flag.String("log-format", string(proxy.LogFormatText), "log format: text or json")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn or error")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		printVersion(os.Stdout)
		return nil
	}

	commands, err := policy.ParseCommands(*allowCommand)
	if err != nil {
		return err
	}

	level, err := parseLevel(*logFormat, *logLevel)
	if err != nil {
		return err
	}
	logger := proxy.NewLogger(proxy.LogFormat(*logFormat), level)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The project is loaded before the socket exists, so a proxy that cannot resolve it is never reachable.
	project, err := compose.Load(ctx, "")
	if err != nil {
		return fmt.Errorf("load compose project: %w", err)
	}
	logger.Info("loaded compose project",
		slog.String("project", project.Name),
		slog.String("working_dir", project.WorkingDir),
		slog.Int("services", len(project.Services)),
	)

	eng, err := engine.New(*dockerHost)
	if err != nil {
		return fmt.Errorf("open the docker client for %s: %w", *dockerHost, err)
	}

	// The Engine's API range is read once, before the socket exists, so a daemon this
	// proxy could not speak to is reported instead of failing every request later.
	versionCtx, cancelVersionQuery := context.WithTimeout(ctx, 10*time.Second)
	defer cancelVersionQuery()
	engineMin, engineMax, err := eng.APIVersions(versionCtx)
	if err != nil {
		return fmt.Errorf("read the API version of the docker daemon at %s: %w", *dockerHost, err)
	}
	if err := policy.CheckEngineAPIVersion(engineMin, engineMax); err != nil {
		return fmt.Errorf("incompatible docker daemon at %s: %w", *dockerHost, err)
	}

	// The policy is built before the socket exists too, for the same reason.
	authz, err := policy.New(policy.Config{
		Project:         project,
		DockerHost:      *dockerHost,
		Listen:          *listen,
		Engine:          eng,
		AllowedCommands: commands,
	})
	if err != nil {
		return fmt.Errorf("build policy: %w", err)
	}
	logger.Info("resolved policy",
		slog.String("docker_host", *dockerHost),
		slog.Any("commands", commands),
		slog.Any("protected_services", authz.ProtectedServices()),
	)

	p := proxy.New(proxy.Config{
		Policy:     authz,
		DockerHost: *dockerHost,
		Logger:     logger,
	})

	mode, err := parseSocketMode(*socketMode)
	if err != nil {
		return err
	}
	listener, err := proxy.Listen(*listen, mode)
	if err != nil {
		return err
	}
	defer func() {
		if err := proxy.Remove(*listen); err != nil {
			logger.Warn("could not remove socket", slog.String("path", *listen), slog.String("error", err.Error()))
		}
	}()

	logger.Info("listening",
		slog.String("socket", *listen),
		slog.String("docker_host", *dockerHost),
	)

	server := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 30 * time.Second,
		// No write timeout, because attach and exec stream as long as the container runs.
	}

	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	return nil
}

func usage() {
	out := flag.CommandLine.Output()
	_, _ = fmt.Fprintf(out, `compose-policy-proxy confines Docker API traffic to a Compose project.

Usage:
  compose-policy-proxy [flags]

The proxy resolves its Compose project from the process working directory and
the process environment, using the same discovery rules as the client. It
therefore deliberately has no option to override the working directory, the
Compose files, the project name, the profiles or the env files: any such
override could make the proxy and the client disagree about what is allowed.

Flags:
`)
	flag.PrintDefaults()
	_, _ = fmt.Fprintf(out, `
Examples:
  # Run the proxy inside a Compose project and let the application reach it.
  compose-policy-proxy --listen /run/compose-policy-proxy/docker.sock

  # Allow only the one-off containers of "docker compose run".
  compose-policy-proxy --allow-command=run
`)
}

func parseLevel(format, level string) (slog.Level, error) {
	if format != string(proxy.LogFormatText) && format != string(proxy.LogFormatJSON) {
		return 0, fmt.Errorf("--log-format must be %q or %q", proxy.LogFormatText, proxy.LogFormatJSON)
	}
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(strings.ToLower(level))); err != nil {
		return 0, fmt.Errorf("--log-level must be debug, info, warn or error: %w", err)
	}
	return parsed, nil
}

func parseSocketMode(s string) (os.FileMode, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0o"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("--socket-mode must be an octal file mode such as 0660: %w", err)
	}
	return os.FileMode(v), nil
}

// Overridden at build time with -ldflags "-X main.version=...". A plain `go build`
// leaves "dev" rather than claiming a release that does not exist.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// printVersion writes one field per line, with the version alone on the first so
// that `--version | head -1` works. Uninjected fields are omitted, never printed.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "compose-policy-proxy %s\n", version)
	if commit != "" && commit != "unknown" {
		_, _ = fmt.Fprintf(w, "commit: %s\n", commit)
	}
	if buildDate != "" && buildDate != "unknown" {
		_, _ = fmt.Fprintf(w, "built: %s\n", buildDate)
	}
}
