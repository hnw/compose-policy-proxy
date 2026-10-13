package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const (
	upgrade = "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n"
	frames  = "stream-1"
	firstIn = "first\n"
	laterIn = "later\n"
)

// Stdin buffered before hijacking and sent after the upgrade must arrive exactly once.
func TestForwardStreamRelaysStdinAroundTheUpgrade(t *testing.T) {
	stdin := make(chan string, 1)
	upstream, daemon := connPair(t)
	go serveAttach(daemon, stdin)

	client, server := connPair(t)
	// What a hijack finds when the client wrote stdin with the request: the bytes are
	// already in the reader, so a copy from it has to send them as well.
	reader := bufio.NewReader(server)
	if _, err := client.Write([]byte(firstIn)); err != nil {
		t.Fatalf("write stdin with the request: %v", err)
	}
	if _, err := reader.Peek(1); err != nil {
		t.Fatalf("no stdin buffered for the hijacked reader: %v", err)
	}

	p := &Proxy{dialer: func(context.Context) (net.Conn, error) { return upstream, nil }}
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		p.forwardStream(&hijackWriter{conn: server, r: reader},
			httptest.NewRequest(http.MethodPost, "http://docker/v1.51/containers/abc/attach?stdin=1&stream=1", nil), nil)
	}()

	clientReader := bufio.NewReader(client)
	resp, err := http.ReadResponse(clientReader, nil)
	if err != nil {
		t.Fatalf("read upgrade: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if _, err := client.Write([]byte(laterIn)); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	closeWrite(client)

	relayed, _ := io.ReadAll(clientReader)
	<-forwarded

	if got := <-stdin; got != firstIn+laterIn {
		t.Errorf("the daemon received stdin %q, want %q once each", got, firstIn+laterIn)
	}
	if string(relayed) != frames {
		t.Errorf("the client received %q, want %q", relayed, frames)
	}
}

// A refused attach is an ordinary HTTP response, and the daemon keeps the
// connection open for reuse. Forwarding must still finish on the body length.
func TestForwardStreamFinishesOnARefusal(t *testing.T) {
	const body = `{"message":"No such container: abc"}`
	upstream, daemon := connPair(t)
	go serveRefusal(daemon, body)

	client, server := connPair(t)
	p := &Proxy{dialer: func(context.Context) (net.Conn, error) { return upstream, nil }}
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		p.forwardStream(&hijackWriter{conn: server, r: bufio.NewReader(server)},
			httptest.NewRequest(http.MethodPost, "http://docker/v1.51/containers/abc/attach?stream=1", nil), nil)
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read refusal body: %v", err)
	}
	if string(got) != body {
		t.Errorf("the client received body %q, want %q", got, body)
	}

	select {
	case <-forwarded:
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy did not finish after forwarding a body with a known length")
	}
}

// serveRefusal answers one refused attach and then holds the connection open, the
// way a daemon that reuses it would.
func serveRefusal(conn net.Conn, body string) {
	defer func() { _ = conn.Close() }()

	if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
		return
	}
	_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)

	_, _ = io.Copy(io.Discard, conn)
}

// serveAttach answers one attach the way a Docker daemon does, then reports the stdin
// the connection carried.
func serveAttach(conn net.Conn, stdin chan<- string) {
	received := ""
	defer func() {
		stdin <- received
		_ = conn.Close()
	}()

	r := bufio.NewReader(conn)
	if _, err := http.ReadRequest(r); err != nil {
		return
	}
	if _, err := io.WriteString(conn, upgrade+frames); err != nil {
		return
	}
	body, _ := io.ReadAll(r)
	received = string(body)
}

// hijackWriter is the ResponseWriter a hijacked request is served through. It hands
// over a connection whose reader already holds the client's first stdin.
type hijackWriter struct {
	conn net.Conn
	r    *bufio.Reader
}

func (h *hijackWriter) Header() http.Header         { return http.Header{} }
func (h *hijackWriter) WriteHeader(int)             {}
func (h *hijackWriter) Write(b []byte) (int, error) { return len(b), nil }

func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(h.r, bufio.NewWriter(h.conn)), nil
}

// connPair returns both ends of one connection, since the proxy ends each direction
// with CloseWrite, which net.Pipe has no answer for.
func connPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	if client, err = net.Dial("tcp", l.Addr().String()); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if server, err = l.Accept(); err != nil {
		t.Fatalf("accept: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}
