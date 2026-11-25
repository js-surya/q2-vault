package proto

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"q2-vault/internal/seal"
	"q2-vault/internal/store"
)

// Backend is the sealed store, as the server needs it.
type Backend interface {
	Get(id string) ([]byte, error)
	Put(id string, b []byte) error
	Delete(id string) error
}

const (
	maxRequest = seal.MaxSecret + 64 + 1 // most bytes ever read
	maxConns   = 32
	deadline   = 5 * time.Second
	drainMax   = 4 << 20
)

// Hooks for tests; production uses the kernel and /proc.
var (
	appID   = AppID
	peerPID = peerPIDOS
)

// Serve listens on the Unix socket until ctx ends. The socket is 0666 (apps
// run as uid 1000, the Vault as root); the caller check, not the file mode,
// is the boundary. One request per connection, a 5 s deadline, and onUse(id)
// for each request answered for an app.
func Serve(ctx context.Context, socket string, b Backend, procRoot string, onUse func(id string)) error {
	os.Remove(socket) // a stale file from a crash
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0o666); err != nil {
		ln.Close()
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()

	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, maxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close() // too many at once
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			handle(c.(*net.UnixConn), b, procRoot, onUse)
		}()
	}
}

func handle(c *net.UnixConn, b Backend, procRoot string, onUse func(string)) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(deadline))

	pid, err := peerPID(c)
	var id string
	if err == nil {
		id, err = appID(procRoot, pid)
	}
	if err != nil {
		reply(c, StatusRefused, nil)
		return
	}

	// Never more than maxRequest bytes into memory.
	req, err := io.ReadAll(io.LimitReader(c, maxRequest))
	if err != nil {
		return // slow or broken client: dropped, no answer
	}
	if len(req) >= maxRequest {
		reply(c, StatusTooLarge, nil)
		drain(c)
		return
	}
	op, body, err := Parse(req)
	if err != nil || (op == "put" && len(body) == 0) {
		reply(c, StatusBadRequest, nil)
		return
	}

	var out []byte
	switch op {
	case "get":
		out, err = b.Get(id)
	case "put":
		err = b.Put(id, body)
	case "delete":
		err = b.Delete(id)
	}
	status := StatusOK
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNone):
		status, out = StatusNone, nil
	case errors.Is(err, store.ErrCardAway):
		status, out = StatusCardAway, nil
	case errors.Is(err, seal.ErrTooLarge):
		status, out = StatusTooLarge, nil
	case errors.Is(err, seal.ErrEmpty):
		status, out = StatusBadRequest, nil
	case errors.Is(err, store.ErrBadID):
		status, out = StatusRefused, nil
	default:
		// An unexpected backend error has no status on the wire and its text
		// must not leak: close with no answer. Clients treat an empty answer
		// as a temporary failure.
		return
	}
	if onUse != nil {
		onUse(id)
	}
	reply(c, status, out)
}

func reply(c *net.UnixConn, status string, body []byte) {
	c.Write(Encode(status, body))
}

// drain reads and discards what an oversized client is still sending, so the
// close does not reset the connection before it has read its answer.
func drain(c *net.UnixConn) {
	c.CloseWrite()
	io.Copy(io.Discard, io.LimitReader(c, drainMax))
}
