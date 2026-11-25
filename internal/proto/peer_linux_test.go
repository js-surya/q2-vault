//go:build linux

package proto

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeerPIDOSReal(t *testing.T) {
	dir, _ := os.MkdirTemp("", "q2v")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer c.Close()
		pid, err := peerPIDOS(c.(*net.UnixConn))
		if err != nil {
			pid = -1
		}
		got <- pid
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if pid := <-got; pid != os.Getpid() {
		t.Errorf("peer pid %d, want %d", pid, os.Getpid())
	}
}

func TestAppIDRejectsTestBinary(t *testing.T) {
	if id, err := AppID("/proc", os.Getpid()); err == nil {
		t.Errorf("the test binary was accepted as %q", id)
	}
}

// SO_PEERCRED end to end: only appID is hooked, the peer pid is the kernel's.
func TestServeRealPeerCred(t *testing.T) {
	var sawPID atomic.Int64
	oldA := appID
	appID = func(_ string, pid int) (string, error) { sawPID.Store(int64(pid)); return "plex", nil }
	t.Cleanup(func() { appID = oldA })
	dir, _ := os.MkdirTemp("", "q2v")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "v.sock")
	f := &fake{data: map[string][]byte{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, sock, f, "/proc", nil) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 200; i++ {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := ask(t, sock, []byte("Q2VAULT/1\nput\nsecret")); string(got) != "Q2VAULT/1\nok\n" {
		t.Fatalf("put: %q", got)
	}
	if int(sawPID.Load()) != os.Getpid() {
		t.Errorf("server saw pid %d, want %d", sawPID.Load(), os.Getpid())
	}
	if string(f.data["plex"]) != "secret" {
		t.Error("not stored")
	}
}
