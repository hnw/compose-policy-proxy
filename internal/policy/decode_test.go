package policy

import (
	"testing"
)

// Strict decoding is what makes a field added to the Moby types fail closed rather
// than pass unseen, so its refusals are tested directly as well as through Authorize.

type knownFields struct {
	Known string `json:"Known"`
}

func TestDecodeRequestAcceptsKnownFields(t *testing.T) {
	var got knownFields
	if err := decodeRequest([]byte(`{"Known":"yes"}`), "test request", &got); err != nil {
		t.Fatalf("a known field should decode, got %v", err)
	}
	if got.Known != "yes" {
		t.Errorf("decoded %+v", got)
	}
}

func TestDecodeRequestRefusesUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		why  string
	}{
		{"unknown field", `{"Unknown":1}`, "which would let it pass unseen"},
		{"trailing content", `{"Known":"a"} {"Known":"b"}`, "a second document in one body"},
		{"malformed json", `{`, "a body that is not JSON at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got knownFields
			err := decodeRequest([]byte(tc.body), "test request", &got)
			if err == nil {
				t.Fatalf("this request was accepted, but %s", tc.why)
			}
			pe, ok := Inspect(err)
			if !ok {
				t.Fatalf("expected a policy refusal, got %v", err)
			}
			if pe.Field != "" {
				t.Errorf("a body that does not decode is not a field difference, got field %q", pe.Field)
			}
		})
	}
}
