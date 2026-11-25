package proto

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
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
	maxPerApp  = 4
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
	// Another Vault answering on the socket is not ours to remove.
	if c, err := net.DialTimeout("unix", socket, time.Second); err == nil {
		c.Close()
		return errors.New("proto: another Vault is already listening")
	}
	os.Remove(socket) // a dead socket from a crash
	// Created 0666 directly: no window, and no chmod by path.
	old := syscall.Umask(0o111)
	ln, err := net.Listen("unix", socket)
	syscall.Umask(old)
	if err != nil {
		return err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false) // unlink by path could hit someone else's file
	mine, _ := os.Lstat(socket)
	defer func() {
		if now, err := os.Lstat(socket); err == nil && mine != nil && os.SameFile(mine, now) {
			os.Remove(socket)
		}
	}()
	go func() { <-ctx.Done(); ln.Close() }()

	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, maxConns)
	pc := &perCaller{n: map[string]int{}}
	backoff := time.Duration(0)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// EMFILE, ENFILE, temporary: back off, keep serving.
			if backoff == 0 {
				backoff = 100 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
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
			handle(c.(*net.UnixConn), b, procRoot, onUse, pc)
		}()
	}
}

func handle(c *net.UnixConn, b Backend, procRoot string, onUse func(string), pc *perCaller) {
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

	if !pc.enter(id) {
		return // this app already has its share open: no answer
	}
	defer pc.leave(id)
	if onUse != nil {
		onUse(id) // every request past the caller check, bad ones too
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
	reply(c, status, out)
}

// perCaller limits concurrent connections per app id.
type perCaller struct {
	mu sync.Mutex
	n  map[string]int
}

func (p *perCaller) enter(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n[id] >= maxPerApp {
		return false
	}
	p.n[id]++
	return true
}

func (p *perCaller) leave(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n[id]--; p.n[id] <= 0 {
		delete(p.n, id)
	}
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
