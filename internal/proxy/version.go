package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/hnw/compose-policy-proxy/internal/policy"
)

// capVersionHeader lowers the API version the client is told to negotiate. A version
// that cannot be read is left alone rather than replaced by a guess.
func capVersionHeader(header http.Header) {
	if capped := policy.CapAPIVersion(header.Get("API-Version")); capped != "" {
		header.Set("API-Version", capped)
	}
}

// capVersionBody lowers the ApiVersion the Engine reported. Only that field is rewritten,
// and the body is decoded field by field so that a field a newer Engine adds survives.
func capVersionBody(resp *http.Response) error {
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// The Engine's bytes are in hand, so its body is replaced by those same bytes. The
	// rewritten copy replaces them in turn when there is one to send.
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(answer))

	var fields map[string]json.RawMessage
	if json.Unmarshal(answer, &fields) != nil {
		return nil
	}
	var reported string
	if json.Unmarshal(fields["ApiVersion"], &reported) != nil {
		return nil
	}
	capped := policy.CapAPIVersion(reported)
	if capped == "" || capped == reported {
		return nil
	}
	fields["ApiVersion"], _ = json.Marshal(capped)
	rewritten, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	// These describe the bytes the Engine sent, which are no longer the bytes sent here.
	resp.Header.Del("Etag")
	resp.Header.Del("Content-Md5")
	return nil
}
