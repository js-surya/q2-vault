// Copied from q2-tailscale/internal/q2spot (same author, MIT), unchanged.
// Package q2spot serves a card app's pages to Q2 Pod over Q2SPOT/1 (q2-pod docs/librespot.md, "Browsing
// protocol"): a Unix stream socket, one request per connection. The client writes
//
//	Q2SPOT/1\n<id>\t<op>\t<arg>…\n
//
// and shuts its write side; the reply is
//
//	Q2SPOT/1\n<id>\t<status>\t<message>\t<cursor>\n
//	<kind>\t<uri>\t<title>\t<subtitle>\t<context>\t<position>\n …
//
// with 0 to 50 rows. In every field %, tab, LF and CR are written %25, %09, %0A and %0D.
package q2spot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Version    = "Q2SPOT/1"
	MaxRequest = 8 << 10  // bytes
	MaxReply   = 64 << 10 // bytes
	MaxRows    = 50
	MaxText    = 255 // a title's or subtitle's bytes
	MaxMessage = 120
	timeout    = 15 * time.Second // the client gives up after this
)

// Row is one row of a list; Kind is the firmware's row kind (list, action, remote, field, info, …).
type Row struct{ Kind, URI, Title, Subtitle, Context, Position string }

// Reply answers a request. Status is ok, unsupported, bad or error; Message one line for the screen,
// or refresh/pages as card apps use it.
type Reply struct {
	Status, Message, Cursor string
	Rows                    []Row
}

// Handler answers one request: its op and its arguments, unescaped.
type Handler func(op string, args []string) Reply

// Escape writes the four reserved bytes as %XX.
func Escape(s string) string {
	if !strings.ContainsAny(s, "%\t\n\r") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%25")
		case '\t':
			b.WriteString("%09")
		case '\n':
			b.WriteString("%0A")
		case '\r':
			b.WriteString("%0D")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var errMalformed = errors.New("q2spot: malformed escape")

// Unescape reads %XX back; a % not followed by two hex digits is malformed.
func Unescape(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errMalformed
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", errMalformed
		}
		b.WriteByte(byte(v))
		i += 2
	}
	return b.String(), nil
}

// cut shortens s to at most n bytes without splitting a UTF-8 character.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// parse reads a request: its id, op and arguments.
func parse(req []byte) (id, op string, args []string, err error) {
	text := string(req)
	head, rest, ok := strings.Cut(text, "\n")
	if !ok || head != Version {
		return "", "", nil, errMalformed
	}
	line, _, _ := strings.Cut(rest, "\n")
	fields := strings.Split(line, "\t")
	if len(fields) < 2 {
		return "", "", nil, errMalformed
	}
	id = fields[0]
	if _, err := strconv.ParseUint(id, 10, 32); err != nil {
		return "", "", nil, errMalformed
	}
	if op, err = Unescape(fields[1]); err != nil || op == "" {
		return id, "", nil, errMalformed
	}
	for _, f := range fields[2:] {
		a, err := Unescape(f)
		if err != nil {
			return id, "", nil, errMalformed
		}
		args = append(args, a)
	}
	return id, op, args, nil
}

// encode writes a reply, its rows kept within MaxRows and MaxReply.
func encode(id string, r Reply) []byte {
	var b bytes.Buffer
	b.WriteString(Version + "\n")
	b.WriteString(id + "\t" + Escape(r.Status) + "\t" + Escape(cut(r.Message, MaxMessage)) + "\t" + Escape(r.Cursor) + "\n")
	for i, row := range r.Rows {
		if i == MaxRows {
			break
		}
		line := strings.Join([]string{Escape(row.Kind), Escape(row.URI), Escape(cut(row.Title, MaxText)),
			Escape(cut(row.Subtitle, MaxText)), Escape(row.Context), Escape(row.Position)}, "\t") + "\n"
		if b.Len()+len(line) > MaxReply {
			break
		}
		b.WriteString(line)
	}
	return b.Bytes()
}

// answer reads one request from c and writes its reply.
func answer(c net.Conn, h Handler) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	req, err := io.ReadAll(io.LimitReader(c, MaxRequest+1))
	id := "0"
	var reply Reply
	switch {
	case err != nil:
		return
	case len(req) > MaxRequest:
		reply = Reply{Status: "bad", Message: "request too long"}
		if i, _, ok := strings.Cut(strings.TrimPrefix(string(req), Version+"\n"), "\t"); ok {
			if _, err := strconv.ParseUint(i, 10, 32); err == nil {
				id = i
			}
		}
	default:
		var op string
		var args []string
		var perr error
		var pid string
		pid, op, args, perr = parse(req)
		if pid != "" {
			id = pid
		}
		if perr != nil {
			reply = Reply{Status: "bad", Message: "malformed request"}
		} else {
			reply = h(op, args)
		}
	}
	c.Write(encode(id, reply))
}

// Serve listens on socket (a stale socket file is replaced) and answers each connection with h until
// ctx ends, then removes the socket.
func Serve(ctx context.Context, socket string, h Handler) error {
	os.Remove(socket)
	l, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go answer(c, h)
	}
}
