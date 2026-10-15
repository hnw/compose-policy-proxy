package policy

import (
	"errors"
	"fmt"
)

// Error is returned for every denial. Field names the Docker field the request got
// wrong, and is empty when the refusal is not about a field at all.
type Error struct {
	Service string
	Field   string
	Detail  string
}

func (e *Error) Error() string {
	var where string
	switch {
	case e.Service != "" && e.Field != "":
		where = fmt.Sprintf("service %q: %s", e.Service, e.Field)
	case e.Field != "":
		where = e.Field
	case e.Service != "":
		where = fmt.Sprintf("service %q", e.Service)
	}
	switch {
	case where == "":
		return e.Detail
	case e.Detail == "":
		return where
	default:
		return where + ": " + e.Detail
	}
}

func denyf(service, field, format string, args ...any) *Error {
	return &Error{Service: service, Field: field, Detail: fmt.Sprintf(format, args...)}
}

func deny(service, field, detail string) *Error {
	return &Error{Service: service, Field: field, Detail: detail}
}

// Malformed reports a request the policy could not decide on at all, such as an
// unreadable or oversized body, or one that does not decode.
func Malformed(format string, args ...any) error {
	return denyf("", "", format, args...)
}

// errUnhandledEndpoint refuses an allowlisted endpoint that no decision rule
// covers. The endpoint is already in the Decision and the log line.
var errUnhandledEndpoint = denyf("", "",
	"no authorization rule covers this docker API operation")

// Inspect reports whether err is a policy denial and returns it as *Error.
func Inspect(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
