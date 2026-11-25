package proto

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
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
	// A refused caller's request is read (refusedDrain at most) after its connection has given back
	// its slot, maxDrains at a time; beyond that it is closed at once.
	refusedDrain = 100 * time.Millisecond
	maxDrains    = 4
)

// ownerIsRoot says whether a file belongs to uid 0; a variable for tests.
var ownerIsRoot = func(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// Hooks for tests; production uses the kernel and /proc.
var (
	appID   = AppID
	peerPID = peerPIDOS
)

// Listener is the Vault's socket, bound and listening.
type Listener struct {
	*net.UnixListener
	path string
	mine os.FileInfo
}

// Close stops listening and removes the socket file, if it is still the one
// Listen made (unlink by path could hit someone else's file).
func (l *Listener) Close() error {
	err := l.UnixListener.Close()
	if now, serr := os.Lstat(l.path); serr == nil && l.mine != nil && os.SameFile(l.mine, now) {
		os.Remove(l.path)
	}
	return err
}

// Listen binds the Unix socket, 0666 (apps run as uid 1000, the Vault as
// root); the caller check, not the file mode, is the boundary. The umask is
// narrowed only for the bind: call it before anything else creates files.
func Listen(socket string) (*Listener, error) {
	// A live socket owned by root is another Vault: not ours to remove. One
	// owned by anyone else was bound by an app while the Vault was down
	// (squatting): it goes, and we take the path.
	if c, err := net.DialTimeout("unix", socket, time.Second); err == nil {
		c.Close()
		if fi, err := os.Lstat(socket); err == nil && fi.Mode()&os.ModeSocket != 0 && ownerIsRoot(fi) {
			return nil, errors.New("proto: another Vault is already listening")
		}
	}
	if err := ClearPath(socket); err != nil {
		return nil, err
	}
	// Created 0666 directly: no window, and no chmod by path.
	old := syscall.Umask(0o111)
	ln, err := net.Listen("unix", socket)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false) // Close unlinks, and only our own file
	mine, _ := os.Lstat(socket)
	return &Listener{UnixListener: ul, path: socket, mine: mine}, nil
}

// ClearPath makes way for a socket at path: a stale file goes, and a folder
// (which os.Remove can't take when it isn't empty) is renamed aside as
// <path>.bad.<pid>, so a folder planted there can't keep the Vault down.
func ClearPath(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil // nothing there (or nothing we can see): Listen says
	}
	if fi.IsDir() {
		return os.Rename(path, path+".bad."+strconv.Itoa(os.Getpid()))
	}
	os.Remove(path) // a dead socket from a crash
	return nil
}

// Serve listens on the Unix socket (Listen) and serves it (ServeOn).
func Serve(ctx context.Context, socket string, b Backend, procRoot string, onUse func(id string)) error {
	l, err := Listen(socket)
	if err != nil {
		return err
	}
	return ServeOn(ctx, l, b, procRoot, onUse)
}

// ServeOn answers on l until ctx ends, then closes l. One request per
// connection, a 5 s deadline, and onUse(id) for each request answered for an
// app. When ctx ends, every open connection's deadline is moved to now, so
// Serve returns at once (the launcher KILLs 2 s after its TERM); a store
// write in progress still finishes, only its answer is lost.
func ServeOn(ctx context.Context, l *Listener, b Backend, procRoot string, onUse func(id string)) error {
	defer l.Close()
	go func() { <-ctx.Done(); l.UnixListener.Close() }()
	open := &conns{m: map[*net.UnixConn]struct{}{}}
	stop := context.AfterFunc(ctx, open.cut)
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, maxConns)
	drains := make(chan struct{}, maxDrains)
	pc := &perCaller{n: map[string]int{}}
	backoff := time.Duration(0)
	for {
		c, err := l.Accept()
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
		uc := c.(*net.UnixConn)
		// The 5 s deadline is set here, before add: a cut at shutdown always
		// comes after it, never overwritten by it.
		uc.SetDeadline(time.Now().Add(deadline))
		open.add(uc)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer open.remove(uc)
			refused := handle(uc, b, procRoot, onUse, pc)
			<-sem // a refused caller doesn't keep its slot while its request is read
			if refused {
				drainRefused(uc, drains)
			}
		}()
	}
}

// conns is the set of open connections, cut at shutdown.
type conns struct {
	mu      sync.Mutex
	stopped bool
	m       map[*net.UnixConn]struct{}
}

func (o *conns) add(c *net.UnixConn) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[c] = struct{}{}
	if o.stopped {
		c.SetDeadline(time.Now())
	}
}

func (o *conns) remove(c *net.UnixConn) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.m, c)
}

// cut moves every open connection's deadline to now, and each later one's
// as it is added.
func (o *conns) cut() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stopped = true
	for c := range o.m {
		c.SetDeadline(time.Now())
	}
}

// handle answers one connection and closes it, except a refused one (true), left to drainRefused.
func handle(c *net.UnixConn, b Backend, procRoot string, onUse func(string), pc *perCaller) (refused bool) {
	defer func() {
		if !refused {
			c.Close()
		}
	}()

	pid, err := peerPID(c)
	var id string
	if err == nil {
		id, err = appID(procRoot, pid)
	}
	if err != nil {
		reply(c, StatusRefused, nil)
		return true
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
	return false
}

// drainRefused reads what a refused caller sent (refusedDrain at most) before closing: on Linux,
// closing with its request unread resets the connection, and the caller loses the answer. Only
// maxDrains at once, so callers the Vault can't identify (not counted per app) can't tie it up;
// beyond that the connection is closed at once.
func drainRefused(c *net.UnixConn, drains chan struct{}) {
	defer c.Close()
	select {
	case drains <- struct{}{}:
		defer func() { <-drains }()
		c.SetReadDeadline(time.Now().Add(refusedDrain))
		drain(c)
	default:
	}
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
