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

func TestAppID(t *testing.T) {
	root := t.TempDir()
	link := func(pid int, target string) {
		d := filepath.Join(root, strconv.Itoa(pid))
		os.MkdirAll(d, 0o755)
		if err := os.Symlink(target, filepath.Join(d, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		target string
		id     string
		ok     bool
	}{
		{"/mnt/mmc/.plex/q2-plex", "plex", true},
		{"/mnt/mmc/.plex/q2-plex (deleted)", "plex", true},
		{"/mnt/mmc/.my-app-1/q2-my-app-1", "my-app-1", true},
		{"/mnt/mmc/.plex/q2-other", "", false},
		{"/mnt/mmc/.vault/q2-vault", "", false},
		{"/usr/bin/sh", "", false},
		{"/mnt/mmc/.Plex/q2-Plex", "", false},
		{"/mnt/mmc/.a/b/q2-b", "", false},
		{"/mnt/mmc/.abcdefghijklmnop/q2-abcdefghijklmnop", "", false},
		{"/mnt/mmc/../mmc/.plex/q2-plex", "", false},
		{"/mnt/mmc/.plex/q2-plex/", "", false},
		{"/mnt/mmc/./q2-", "", false},
	}
	for i, c := range cases {
		pid := 100 + i
		link(pid, c.target)
		id, err := AppID(root, pid)
		if c.ok && (err != nil || id != c.id) {
			t.Errorf("%q: %q %v", c.target, id, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%q should be refused, got %q", c.target, id)
		}
	}
	if _, err := AppID(root, 99999); err == nil {
		t.Error("missing pid should fail")
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
	appID = func(_ string, _ int) (string, error) {
		if caller == "" {
			return "", errors.New("not a card app")
		}
		return caller, nil
	}
	peerPID = func(*net.UnixConn) (int, error) {
		if noPeer.Load() {
			return 0, errors.New("no creds")
		}
		return 1, nil
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
	for i := 0; i < 200; i++ {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			return sock
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return ""
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
