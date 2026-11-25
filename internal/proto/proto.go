// Package proto speaks Q2VAULT/1: one request per connection, an app's own
// login only.
package proto

import (
	"bytes"
	"errors"
)

const magic = "Q2VAULT/1\n"

// Answer statuses.
const (
	StatusOK         = "ok"
	StatusNone       = "none"
	StatusRefused    = "refused"
	StatusTooLarge   = "too-large"
	StatusCardAway   = "card-away"
	StatusBadRequest = "bad-request"
)

var errBadRequest = errors.New("proto: bad request")

// Parse splits a request into its op and body. get and delete take no body.
func Parse(req []byte) (op string, body []byte, err error) {
	if !bytes.HasPrefix(req, []byte(magic)) {
		return "", nil, errBadRequest
	}
	rest := req[len(magic):]
	i := bytes.IndexByte(rest, '\n')
	if i < 0 {
		return "", nil, errBadRequest
	}
	op, body = string(rest[:i]), rest[i+1:]
	switch op {
	case "put":
	case "get", "delete":
		if len(body) != 0 {
			return "", nil, errBadRequest
		}
	default:
		return "", nil, errBadRequest
	}
	return op, body, nil
}

// Encode builds an answer.
func Encode(status string, body []byte) []byte {
	out := make([]byte, 0, len(magic)+len(status)+1+len(body))
	out = append(out, magic...)
	out = append(out, status...)
	out = append(out, '\n')
	return append(out, body...)
}
