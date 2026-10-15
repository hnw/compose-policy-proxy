package proxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// A Docker attach keeps writing stdin and reading stdout on the hijacked connection
// after the headers, so streaming endpoints take the client connection over.
func isStreamingEndpoint(endpoint string) bool {
	return strings.HasSuffix(endpoint, "/attach")
}

type dialer func(ctx context.Context) (net.Conn, error)

func (p *Proxy) forwardStream(w http.ResponseWriter, r *http.Request, body []byte) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.writeError(w, http.StatusInternalServerError, "connection cannot be hijacked")
		return
	}

	upstream, err := p.dialer(r.Context())
	if err != nil {
		p.logger.Warn("could not connect to the upstream docker daemon", slog.String("error", err.Error()))
		p.writeError(w, http.StatusBadGateway, "the request to the upstream docker daemon could not be completed")
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		p.writeError(w, http.StatusInternalServerError, "connection cannot be hijacked")
		return
	}

	if err := writeRawRequest(upstream, r, body); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	upReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upReader, r)
	if err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	if resp.StatusCode >= http.StatusBadRequest {
		// HTTP errors may use keep-alive, so copy only the response body.
		_ = resp.Write(clientBuf.Writer)
		_ = clientBuf.Writer.Flush()
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	if err := writeRawResponseHead(clientBuf, resp); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}
	if err := clientBuf.Writer.Flush(); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	// A Docker attach answers "101 UPGRADED" and then raw frames, so there is no HTTP
	// body to copy. Copying from the hijacked reader sends whatever arrived with the
	// headers before the rest of the stream.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientBuf)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upReader)
		closeWrite(clientConn)
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = clientConn.Close()
	_ = upstream.Close()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// writeRawRequest serialises the inbound request onto the upstream connection, keeping
// the API version prefix the daemon validates against.
func writeRawRequest(conn net.Conn, r *http.Request, body []byte) error {
	var b strings.Builder
	b.WriteString(r.Method + " " + r.URL.RequestURI() + " HTTP/1.1\r\n")
	b.WriteString("Host: " + upstreamHost + "\r\n")
	for key, values := range r.Header {
		if strings.EqualFold(key, "Transfer-Encoding") {
			continue
		}
		for _, v := range values {
			b.WriteString(key + ": " + v + "\r\n")
		}
	}
	if len(body) > 0 {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(conn, b.String()); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := conn.Write(body); err != nil {
			return err
		}
	}
	return nil
}

func writeRawResponseHead(w *bufio.ReadWriter, resp *http.Response) error {
	if _, err := w.WriteString(resp.Proto + " " + resp.Status + "\r\n"); err != nil {
		return err
	}
	for key, values := range resp.Header {
		for _, v := range values {
			if _, err := w.WriteString(key + ": " + v + "\r\n"); err != nil {
				return err
			}
		}
	}
	_, err := w.WriteString("\r\n")
	return err
}
