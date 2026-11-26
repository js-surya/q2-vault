package proto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"q2-vault/internal/seal"
	"q2-vault/internal/store"
)

func TestParse(t *testing.T) {
	op, body, err := Parse([]byte("Q2VAULT/1\nget\n"))
	if err != nil || op != "get" || len(body) != 0 {
		t.Fatalf("get: %q %q %v", op, body, err)
	}
	want := []byte("a\nb\x00c\n")
	op, body, err = Parse(append([]byte("Q2VAULT/1\nput\n"), want...))
	if err != nil || op != "put" || !bytes.Equal(body, want) {
		t.Fatalf("put: %q %q %v", op, body, err)
	}
	if op, _, err = Parse([]byte("Q2VAULT/1\ndelete\n")); err != nil || op != "delete" {
		t.Fatalf("delete: %q %v", op, err)
	}
	for _, bad := range []string{
		"", "Q2VAULT/2\nget\n", "Q2SPOT/1\nget\n", "Q2VAULT/1\nfrob\n",
		"Q2VAULT/1\nget\nx", "Q2VAULT/1\ndelete\nx", "Q2VAULT/1\nget", "Q2VAULT/1\n",
	} {
		if _, _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

func TestEncode(t *testing.T) {
	if got := Encode("ok", []byte("s")); string(got) != "Q2VAULT/1\nok\ns" {
		t.Fatalf("%q", got)
	}
	if got := Encode("none", nil); string(got) != "Q2VAULT/1\nnone\n" {
		t.Fatalf("%q", got)
	}
}

func withCard(t *testing.T) string {
	t.Helper()
	old := cardRoot
	cardRoot = t.TempDir()
	// A fixed fake mount namespace for "us", so the result is the same on
	// macOS and on Linux (where the real /proc/self/ns/mnt is readable).
	oldNS := selfNS
	selfNS = filepath.Join(t.TempDir(), "mnt")
	os.Symlink("mnt:[1]", selfNS)
	t.Cleanup(func() { cardRoot, selfNS = old, oldNS })
	return cardRoot
}

func touch(t *testing.T, path string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func fakeProc(t *testing.T, pid int, target string) string {
	t.Helper()
	root := t.TempDir()
	d := filepath.Join(root, strconv.Itoa(pid))
	os.MkdirAll(d, 0o755)
	if err := os.Symlink(target, filepath.Join(d, "exe")); err != nil {
		t.Fatal(err)
	}
	// The fake process shares our fake mount namespace.
	os.MkdirAll(filepath.Join(d, "ns"), 0o755)
	if err := os.Symlink("mnt:[1]", filepath.Join(d, "ns", "mnt")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestAppID(t *testing.T) {
	R := withCard(t)
	touch(t, R+"/.plex/q2-plex")
	touch(t, R+"/.my-app-1/q2-my-app-1")
	cases := []struct {
		target string
		id     string
		ok     bool
	}{
		{R + "/.plex/q2-plex", "plex", true},
		{R + "/.plex/q2-plex (deleted)", "plex", true},
		{R + "/.my-app-1/q2-my-app-1", "my-app-1", true},
		{R + "/.plex/q2-other", "", false},
		{R + "/.vault/q2-vault", "", false},
		{"/usr/bin/sh", "", false},
		{R + "/.Plex/q2-Plex", "", false},
		{R + "/.a/b/q2-b", "", false},
		{R + "/.abcdefghijklmnop/q2-abcdefghijklmnop", "", false},
		{R + "/../" + filepath.Base(R) + "/.plex/q2-plex", "", false},
		{R + "/.plex/q2-plex/", "", false},
		{R + "/./q2-", "", false},
	}
	touch(t, R+"/.vault/q2-vault")
	for _, c := range cases {
		root := fakeProc(t, 100, c.target)
		id, err := AppID(root, 100, 1000)
		if c.ok && (err != nil || id != c.id) {
			t.Errorf("%q: %q %v", c.target, id, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%q should be refused, got %q", c.target, id)
		}
	}
	if _, err := AppID(t.TempDir(), 99999, 1000); err == nil {
		t.Error("missing pid should fail")
	}
}

func TestAppIDInode(t *testing.T) {
	R := withCard(t)
	touch(t, R+"/.plex/q2-plex")
	touch(t, R+"/elsewhere")
	root := fakeProc(t, 7, R+"/.plex/q2-plex")
	// A private mount put another file at the same path: stat of the running
	// exe resolves to a different inode than the card's canonical file.
	old := exeStat
	t.Cleanup(func() { exeStat = old })
	exeStat = func(string) (os.FileInfo, error) { return os.Stat(R + "/elsewhere") }
	if id, err := AppID(root, 7, 1000); err == nil {
		t.Errorf("different inode accepted as %q", id)
	}
	exeStat = func(string) (os.FileInfo, error) { return os.Stat(R + "/.plex/q2-plex") }
	if id, err := AppID(root, 7, 1000); err != nil || id != "plex" {
		t.Errorf("same inode: %q %v", id, err)
	}
}

func TestAppIDNSFailClosed(t *testing.T) {
	R := withCard(t)
	touch(t, R+"/.plex/q2-plex")
	root := fakeProc(t, 7, R+"/.plex/q2-plex")
	os.RemoveAll(filepath.Join(root, "7", "ns")) // peer's ns/mnt unreadable
	self := filepath.Join(t.TempDir(), "mnt")
	os.Symlink("mnt:[1]", self)
	old := selfNS
	t.Cleanup(func() { selfNS = old })
	selfNS = self
	if id, err := AppID(root, 7, 1000); err == nil {
		t.Errorf("unreadable peer namespace accepted as %q", id)
	}
	selfNS = filepath.Join(t.TempDir(), "none") // kernel without ns files
	if id, err := AppID(root, 7, 1000); err != nil || id != "plex" {
		t.Errorf("fallback to inode check: %q %v", id, err)
	}
	// ...and the inode check still bites in that fallback.
	touch(t, R+"/elsewhere")
	oldS := exeStat
	t.Cleanup(func() { exeStat = oldS })
	exeStat = func(string) (os.FileInfo, error) { return os.Stat(R + "/elsewhere") }
	if _, err := AppID(root, 7, 1000); err == nil {
		t.Error("inode mismatch accepted in fallback")
	}
}

func TestAppIDMountNS(t *testing.T) {
	R := withCard(t)
	touch(t, R+"/.plex/q2-plex")
	root := fakeProc(t, 7, R+"/.plex/q2-plex")
	os.Remove(filepath.Join(root, "7", "ns", "mnt"))
	os.Symlink("mnt:[2]", filepath.Join(root, "7", "ns", "mnt"))
	self := filepath.Join(t.TempDir(), "mnt")
	os.Symlink("mnt:[1]", self)
	old := selfNS
	t.Cleanup(func() { selfNS = old })
	selfNS = self
	if id, err := AppID(root, 7, 1000); err == nil {
		t.Errorf("other mount namespace accepted as %q", id)
	}
	os.Remove(self)
	os.Symlink("mnt:[2]", self)
	if id, err := AppID(root, 7, 1000); err != nil || id != "plex" {
		t.Errorf("same namespace: %q %v", id, err)
	}
}

var noPeer atomic.Bool

type fake struct {
	mu   sync.Mutex
	data map[string][]byte
	err  error
}

func (f *fake) setErr(e error) { f.mu.Lock(); f.err = e; f.mu.Unlock() }

func (f *fake) Get(id string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.data[id]
	if !ok {
		return nil, store.ErrNone
	}
	return b, nil
}
func (f *fake) Put(id string, b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if len(b) == 0 {
		return seal.ErrEmpty
	}
	if len(b) > seal.MaxSecret {
		return seal.ErrTooLarge
	}
	f.data[id] = append([]byte(nil), b...)
	return nil
}
func (f *fake) Delete(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	delete(f.data, id)
	return nil
}

func start(t *testing.T, f *fake, caller string, used *[]string, mu *sync.Mutex) string {
	t.Helper()
	oldA, oldP := appID, peerPID
	appID = func(_ string, _, _ int) (string, error) {
		if caller == "" {
			return "", errors.New("not a card app")
		}
		return caller, nil
	}
	peerPID = func(*net.UnixConn) (int, int, error) {
		if noPeer.Load() {
			return 0, 0, errors.New("no creds")
		}
		return 1, 1000, nil
	}
	noPeer.Store(false)
	t.Cleanup(func() { appID, peerPID = oldA, oldP })
	// Short path: a Unix socket name is limited to ~104 bytes on macOS.
	dir, err := os.MkdirTemp("", "q2v")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "v.sock")
	os.WriteFile(sock, []byte("stale"), 0o600) // stale file must be replaced
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, sock, f, "/proc", func(id string) {
			if used != nil {
				mu.Lock()
				*used = append(*used, id)
				mu.Unlock()
			}
		})
	}()
	t.Cleanup(func() { cancel(); <-done })
	// Ready once the stale file is a socket: no probe connection, so onUse
	// counts only the test's own requests.
	for i := 0; i < 200; i++ {
		if fi, err := os.Lstat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return sock
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return ""
}

// poll waits up to 2 s for cond.
func poll(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func ask(t *testing.T, sock string, req []byte) []byte {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write(req)
	c.(*net.UnixConn).CloseWrite()
	b, _ := io.ReadAll(c)
	return b
}

func TestServe(t *testing.T) {
	f := &fake{data: map[string][]byte{}}
	var used []string
	var mu sync.Mutex
	sock := start(t, f, "plex", &used, &mu)

	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o666 {
		t.Errorf("socket mode %v", fi.Mode().Perm())
	}
	eq := func(name string, got []byte, want string) {
		t.Helper()
		if string(got) != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
	eq("none", ask(t, sock, []byte("Q2VAULT/1\nget\n")), "Q2VAULT/1\nnone\n")
	eq("put", ask(t, sock, []byte("Q2VAULT/1\nput\ntok\nen")), "Q2VAULT/1\nok\n")
	eq("get", ask(t, sock, []byte("Q2VAULT/1\nget\n")), "Q2VAULT/1\nok\ntok\nen")
	if string(f.data["plex"]) != "tok\nen" || len(f.data) != 1 {
		t.Errorf("stored under the caller only: %v", f.data)
	}
	eq("delete", ask(t, sock, []byte("Q2VAULT/1\ndelete\n")), "Q2VAULT/1\nok\n")
	eq("delete again", ask(t, sock, []byte("Q2VAULT/1\ndelete\n")), "Q2VAULT/1\nok\n")
	eq("bad op", ask(t, sock, []byte("Q2VAULT/1\nfrob\n")), "Q2VAULT/1\nbad-request\n")
	eq("garbage", ask(t, sock, []byte("hello")), "Q2VAULT/1\nbad-request\n")
	eq("empty put", ask(t, sock, []byte("Q2VAULT/1\nput\n")), "Q2VAULT/1\nbad-request\n")
	eq("max put", ask(t, sock, append([]byte("Q2VAULT/1\nput\n"), make([]byte, 16384)...)), "Q2VAULT/1\nok\n")
	eq("16385", ask(t, sock, append([]byte("Q2VAULT/1\nput\n"), make([]byte, 16385)...)), "Q2VAULT/1\ntoo-large\n")

	big := make([]byte, 1<<20)
	eq("1MB", ask(t, sock, append([]byte("Q2VAULT/1\nput\n"), big...)), "Q2VAULT/1\ntoo-large\n")

	f.setErr(store.ErrCardAway)
	eq("card-away get", ask(t, sock, []byte("Q2VAULT/1\nget\n")), "Q2VAULT/1\ncard-away\n")
	eq("card-away put", ask(t, sock, []byte("Q2VAULT/1\nput\nx")), "Q2VAULT/1\ncard-away\n")
	f.setErr(store.ErrBadID)
	eq("bad id", ask(t, sock, []byte("Q2VAULT/1\nget\n")), "Q2VAULT/1\nrefused\n")
	// Unexpected backend error: no answer at all, nothing leaked.
	f.setErr(errors.New("disk /mnt/mmc/.q2vault exploded"))
	eq("internal", ask(t, sock, []byte("Q2VAULT/1\nget\n")), "")
	f.setErr(nil)

	mu.Lock()
	defer mu.Unlock()
	if len(used) == 0 {
		t.Error("onUse never called")
	}
	for _, id := range used {
		if id != "plex" {
			t.Errorf("onUse(%q)", id)
		}
	}
}

func TestServeRefusesNonApp(t *testing.T) {
	f := &fake{data: map[string][]byte{"plex": []byte("s")}}
	var used []string
	var mu sync.Mutex
	sock := start(t, f, "", &used, &mu)
	if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) != "Q2VAULT/1\nrefused\n" {
		t.Errorf("got %q", got)
	}
	if len(used) != 0 {
		t.Errorf("onUse for a refused caller: %v", used)
	}
}

func TestServeRefusesWhenPeerUnknown(t *testing.T) {
	f := &fake{data: map[string][]byte{}}
	sock := start(t, f, "plex", nil, nil)
	noPeer.Store(true)
	if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) != "Q2VAULT/1\nrefused\n" {
		t.Errorf("got %q", got)
	}
}

func TestServeSlowClient(t *testing.T) {
	f := &fake{data: map[string][]byte{}}
	sock := start(t, f, "plex", nil, nil)
	slow, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	// Others are answered while the slow one hangs.
	if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) != "Q2VAULT/1\nnone\n" {
		t.Errorf("got %q", got)
	}
	start := time.Now()
	slow.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, _ := io.Copy(io.Discard, slow)
	el := time.Since(start)
	if n != 0 || el < 4*time.Second || el > 7*time.Second {
		t.Errorf("slow client: %d bytes, closed after %v", n, el)
	}
	if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) != "Q2VAULT/1\nnone\n" {
		t.Errorf("after: %q", got)
	}
}

func TestServeOneVaultOnly(t *testing.T) {
	f := &fake{data: map[string][]byte{}}
	sock := start(t, f, "plex", nil, nil)
	oldO := ownerIsRoot
	ownerIsRoot = func(os.FileInfo) bool { return true } // the test can't be root
	t.Cleanup(func() { ownerIsRoot = oldO })
	err := Serve(context.Background(), sock, f, "/proc", nil)
	if err == nil {
		t.Fatal("second Serve on a live socket should fail")
	}
	if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) != "Q2VAULT/1\nnone\n" {
		t.Errorf("first Vault damaged: %q", got)
	}
}

func TestServeLeavesReplacedSocket(t *testing.T) {
	f := &fake{data: map[string][]byte{}}
	var cancel context.CancelFunc
	oldA, oldP := appID, peerPID
	appID = func(string, int, int) (string, error) { return "plex", nil }
	peerPID = func(*net.UnixConn) (int, int, error) { return 1, 1000, nil }
	t.Cleanup(func() { appID, peerPID = oldA, oldP })
	dir, _ := os.MkdirTemp("", "q2v")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "v.sock")
	var ctx context.Context
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, sock, f, "/proc", nil) }()
	for i := 0; i < 200; i++ {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Remove(sock)
	os.WriteFile(sock, []byte("not ours"), 0o600)
	cancel()
	<-done
	if b, err := os.ReadFile(sock); err != nil || string(b) != "not ours" {
		t.Errorf("another file at the path was removed: %v", err)
	}
}

func TestServePerCallerCap(t *testing.T) {
	f := &fake{data: map[string][]byte{}}
	var used []string
	var mu sync.Mutex
	sock := start(t, f, "plex", &used, &mu)
	uses := func() int { mu.Lock(); defer mu.Unlock(); return len(used) }
	var held []net.Conn
	for i := 0; i < maxPerApp; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		defer c.Close()
	}
	// Every held connection is past enter (onUse fires right after it).
	poll(t, "the held connections to be taken", func() bool { return uses() == maxPerApp })
	start := time.Now()
	if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); len(got) != 0 || time.Since(start) > 2*time.Second {
		t.Errorf("over the cap: %q after %v", got, time.Since(start))
	}
	if n := uses(); n != maxPerApp {
		t.Errorf("onUse for a connection over the cap: %d calls", n)
	}
	for _, c := range held {
		c.Close()
	}
	// Released as each held handler ends: answered again within 2 s.
	poll(t, "an answer after release", func() bool {
		return string(ask(t, sock, []byte("Q2VAULT/1\nget\n"))) == "Q2VAULT/1\nnone\n"
	})
}

func TestServeShutdownCutsOpenConnections(t *testing.T) {
	oldA, oldP := appID, peerPID
	appID = func(string, int, int) (string, error) { return "plex", nil }
	peerPID = func(*net.UnixConn) (int, int, error) { return 1, 1000, nil }
	t.Cleanup(func() { appID, peerPID = oldA, oldP })
	dir, _ := os.MkdirTemp("", "q2v")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "v.sock")
	var uses atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, sock, &fake{data: map[string][]byte{}}, "/proc", func(string) { uses.Add(1) })
	}()
	poll(t, "the socket", func() bool { fi, err := os.Lstat(sock); return err == nil && fi.Mode()&os.ModeSocket != 0 })
	// Two slow clients: each holds its connection, sending nothing.
	for range 2 {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	poll(t, "the slow clients to be taken", func() bool { return uses.Load() == 2 })
	t0 := time.Now()
	cancel() // TERM: Serve must not wait out their 5 s deadline (the launcher KILLs after 2 s)
	select {
	case <-done:
		if el := time.Since(t0); el > time.Second {
			t.Fatalf("Serve took %v to return", el)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Serve still waiting on open connections")
	}
}

func TestServeSetsAsideADirectoryAtItsPath(t *testing.T) {
	oldA, oldP := appID, peerPID
	appID = func(string, int, int) (string, error) { return "plex", nil }
	peerPID = func(*net.UnixConn) (int, int, error) { return 1, 1000, nil }
	t.Cleanup(func() { appID, peerPID = oldA, oldP })
	dir, _ := os.MkdirTemp("", "q2v")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "v.sock")
	// A folder planted at the path, not empty: os.Remove can't take it.
	if err := os.MkdirAll(filepath.Join(sock, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, sock, &fake{data: map[string][]byte{}}, "/proc", nil) }()
	t.Cleanup(func() { cancel(); <-done })
	poll(t, "the socket in place of the folder", func() bool {
		fi, err := os.Lstat(sock)
		return err == nil && fi.Mode()&os.ModeSocket != 0
	})
	aside := sock + ".bad." + strconv.Itoa(os.Getpid())
	if fi, err := os.Stat(filepath.Join(aside, "inside")); err != nil || !fi.IsDir() {
		t.Fatalf("folder not set aside as %s: %v", aside, err)
	}
	if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) != "Q2VAULT/1\nnone\n" {
		t.Fatalf("get: %q", got)
	}
}

func TestOnUseForBadRequest(t *testing.T) {
	f := &fake{data: map[string][]byte{}}
	var used []string
	var mu sync.Mutex
	sock := start(t, f, "plex", &used, &mu)
	ask(t, sock, []byte("garbage"))
	mu.Lock()
	defer mu.Unlock()
	if len(used) == 0 {
		t.Error("onUse not called for a bad request from an app")
	}
}

func TestServeRemovesSquatterSocket(t *testing.T) {
	dir, _ := os.MkdirTemp("", "q2v")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "v.sock")
	squat, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer squat.Close()
	go func() {
		for {
			c, err := squat.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	oldO := ownerIsRoot
	t.Cleanup(func() { ownerIsRoot = oldO })
	// With a root-owned live socket it must refuse.
	ownerIsRoot = func(os.FileInfo) bool { return true }
	if err := Serve(context.Background(), sock, &fake{}, "/proc", nil); err == nil {
		t.Fatal("a live root-owned socket should stop Serve")
	}
	ownerIsRoot = func(os.FileInfo) bool { return false }
	oldA, oldP := appID, peerPID
	appID = func(string, int, int) (string, error) { return "plex", nil }
	peerPID = func(*net.UnixConn) (int, int, error) { return 1, 1000, nil }
	t.Cleanup(func() { appID, peerPID = oldA, oldP })
	f := &fake{data: map[string][]byte{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, sock, f, "/proc", nil) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 200; i++ {
		if got := ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) == "Q2VAULT/1\nnone\n" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Serve did not take the squatted path")
}

func TestRefusedCallersCantHoldTheLine(t *testing.T) {
	// 40 refused callers that send nothing and never close: a valid caller is
	// still answered at once (each refused one held a slot for 1 s before).
	var refuse atomic.Bool
	var refusals atomic.Int32
	oldA, oldP := appID, peerPID
	appID = func(string, int, int) (string, error) {
		if refuse.Load() {
			refusals.Add(1)
			return "", errors.New("not a card app")
		}
		return "plex", nil
	}
	peerPID = func(*net.UnixConn) (int, int, error) { return 1, 1000, nil }
	t.Cleanup(func() { appID, peerPID = oldA, oldP })
	dir, _ := os.MkdirTemp("", "q2v")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "v.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, sock, &fake{data: map[string][]byte{}}, "/proc", nil) }()
	t.Cleanup(func() { cancel(); <-done })
	poll(t, "the socket", func() bool { fi, err := os.Lstat(sock); return err == nil && fi.Mode()&os.ModeSocket != 0 })
	refuse.Store(true)
	for range 40 {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	// Every one refused (none taken as plex once refuse is off, which would hold plex's own share);
	// before this fix only 32 got as far, the rest closed for want of a slot.
	poll(t, "all 40 refusals", func() bool { return refusals.Load() == 40 })
	refuse.Store(false)
	// Answered within 300 ms (a refused one being handled may hold its slot for an instant; before
	// this fix each held one for a second).
	start := time.Now()
	var got []byte
	for time.Since(start) < 300*time.Millisecond {
		if got = ask(t, sock, []byte("Q2VAULT/1\nget\n")); string(got) == "Q2VAULT/1\nnone\n" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("valid caller after 40 refused ones: %q for %v", got, time.Since(start))
}
