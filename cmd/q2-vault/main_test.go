package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"q2-vault/internal/missing"
	"q2-vault/internal/proto"
	"q2-vault/internal/store"
)

// clock is a fake clock the test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fixture is a card (mounted), a keys folder and a /tmp, all temporary. Sockets
// go under /tmp itself: macOS caps a socket path at 104 bytes.
func fixture(t *testing.T) (config, *clock) {
	t.Helper()
	root := t.TempDir()
	card := filepath.Join(root, "mmc")
	if err := os.MkdirAll(filepath.Join(card, ".vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(root, "mounts")
	if err := os.WriteFile(mounts, []byte("/dev/mmcblk0p1 "+card+" exfat rw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	socks, err := os.MkdirTemp("/tmp", "qv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socks) })
	tmp := filepath.Join(root, "tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}
	// Firmware that starts the Vault with the app that needs it: idle exit is on.
	caps := filepath.Join(tmp, "q2-addon.caps")
	if err := os.WriteFile(caps, []byte("art now needs window\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return config{
		Caps:      caps,
		capsOwner: func(os.FileInfo) bool { return true }, // the test can't make root's files
		Dir:       filepath.Join(card, ".vault"),
		Card:      card,
		Sealed:    filepath.Join(card, ".q2vault"),
		Keys:      filepath.Join(root, "data", "apps", "vault"),
		Socket:    filepath.Join(socks, "v.sock"),
		Browse:    filepath.Join(socks, "b.sock"),
		Tmp:       tmp,
		Mounts:    mounts,
		Proc:      filepath.Join(root, "proc"),
		Now:       clk.Now,
		Tick:      10 * time.Millisecond,
		Logf:      t.Logf,
	}, clk
}

// asPlex is proto's server with the caller check replaced: every caller is the
// app "plex" (peer credentials and /proc/<pid>/exe can't be faked in a test).
func asPlex(ctx context.Context, ln *proto.Listener, b proto.Backend, _ string, onUse func(string)) error {
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			req, _ := io.ReadAll(c)
			onUse("plex")
			op, body, err := proto.Parse(req)
			if err != nil {
				c.Write(proto.Encode(proto.StatusBadRequest, nil))
				return
			}
			var out []byte
			switch op {
			case "get":
				out, err = b.Get("plex")
			case "put":
				err = b.Put("plex", body)
			case "delete":
				err = b.Delete("plex")
			}
			status := proto.StatusOK
			if err != nil {
				status, out = proto.StatusNone, nil
			}
			c.Write(proto.Encode(status, out))
		}()
	}
}

// ask sends one Q2VAULT/1 request and returns the answer.
func ask(t *testing.T, socket, op string, body []byte) string {
	t.Helper()
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(append([]byte("Q2VAULT/1\n"+op+"\n"), body...))
	c.(*net.UnixConn).CloseWrite()
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// start runs the app in the background; the returned channel gives run's error.
func start(t *testing.T, ctx context.Context, cfg config) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()
	waitFor(t, "the sockets", func() bool { return exists(cfg.Socket) && exists(cfg.Browse) })
	return done
}

func TestRunServesAndExitsWhenIdle(t *testing.T) {
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	var mu sync.Mutex
	var before, after [32]byte
	wiped := 0
	orig := wipe
	wipe = func(k *[32]byte) {
		mu.Lock()
		defer mu.Unlock()
		before = *k
		orig(k)
		after = *k
		wiped++
	}
	t.Cleanup(func() { wipe = orig })
	stopped := false
	cfg.OnStop = func() { stopped = true }

	done := start(t, context.Background(), cfg)
	secret := []byte(`{"token":"abc"}`)
	if got := ask(t, cfg.Socket, "put", secret); got != "Q2VAULT/1\nok\n" {
		t.Fatalf("put: %q", got)
	}
	if got := ask(t, cfg.Socket, "get", nil); got != "Q2VAULT/1\nok\n"+string(secret) {
		t.Fatalf("get: %q", got)
	}
	blob, err := os.ReadFile(filepath.Join(cfg.Sealed, "plex.sealed"))
	if err != nil || bytes.Contains(blob, secret) {
		t.Fatalf("sealed file: %v, plaintext inside: %v", err, bytes.Contains(blob, secret))
	}
	key, err := os.ReadFile(filepath.Join(cfg.Keys, "key"))
	if err != nil || len(key) != 32 {
		t.Fatalf("key file: %v, %d bytes", err, len(key))
	}

	// No app uses it: still running at 59 s (the page's minute isn't over),
	// closed after 60 s.
	clk.Add(59 * time.Second)
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("closed before the page's minute: %v", err)
	default:
	}
	clk.Add(2 * time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running when idle")
	}
	mu.Lock()
	defer mu.Unlock()
	if wiped != 1 || before == ([32]byte{}) || after != ([32]byte{}) || !bytes.Equal(before[:], key) {
		t.Fatalf("key not wiped: %d calls, before set %v, after zero %v", wiped, before != [32]byte{}, after == [32]byte{})
	}
	if exists(cfg.Socket) || exists(cfg.Browse) {
		t.Fatal("a socket left behind")
	}
	if stopped {
		t.Fatal("the removal watch started on an idle close")
	}
}

func TestRunStaysWhileAnAppRuns(t *testing.T) {
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	// .plex says needs=vault, and its pid file names this (live) process.
	plex := filepath.Join(cfg.Card, ".plex")
	os.MkdirAll(plex, 0o755)
	os.WriteFile(filepath.Join(plex, "q2app"), []byte("name=Plex\nneeds=vault\n"), 0o644)
	os.WriteFile(filepath.Join(cfg.Tmp, "q2-plex"), []byte("1234\n"), 0o644)
	os.MkdirAll(filepath.Join(cfg.Proc, "1234"), 0o755)
	cfg.running = func(tmp, id string) bool { return id == "plex" && exists(filepath.Join(cfg.Proc, "1234")) }

	done := start(t, context.Background(), cfg)
	for range 3 {
		clk.Add(40 * time.Second)
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("closed while an app that needs it runs: %v", err)
	default:
	}
	os.RemoveAll(filepath.Join(cfg.Proc, "1234")) // plex stops
	time.Sleep(50 * time.Millisecond)
	clk.Add(61 * time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running after the app stopped")
	}
}

func TestRunRealSocketRefusesAndStopsOnTerm(t *testing.T) {
	cfg, _ := fixture(t)
	stopped := make(chan struct{})
	cfg.OnStop = func() { close(stopped) }
	ctx, cancel := context.WithCancel(context.Background())
	done := start(t, ctx, cfg)
	// Apps (uid 1000) reach the Vault's socket; only the firmware's UI (root) the page's.
	for path, want := range map[string]os.FileMode{cfg.Socket: 0o666, cfg.Browse: 0o600} {
		if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v (%v)", filepath.Base(path), fi.Mode().Perm(), want, err)
		}
	}
	// The test process is no card app: proto's own server refuses it.
	if got := ask(t, cfg.Socket, "get", nil); got != "Q2VAULT/1\nrefused\n" {
		t.Fatalf("get from a non-app: %q", got)
	}
	cancel() // TERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running after TERM")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("no removal watch on TERM")
	}
	if exists(cfg.Socket) || exists(cfg.Browse) {
		t.Fatal("a socket left behind")
	}
}

func TestStartCleansTmpAndSweeps(t *testing.T) {
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	if err := os.MkdirAll(cfg.Sealed, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"jelly.sealed", "gone.sealed", "new.sealed", "cut.sealed.tmp"} {
		os.WriteFile(filepath.Join(cfg.Sealed, n), []byte("x"), 0o600)
	}
	// jelly is installed; gone has been missing 8 days; new goes missing today.
	os.MkdirAll(filepath.Join(cfg.Card, ".jelly"), 0o755)
	os.WriteFile(filepath.Join(cfg.Card, ".jelly", "q2-jelly"), []byte("bin"), 0o755)
	os.MkdirAll(cfg.Keys, 0o700)
	st := missing.State{Missing: map[string]time.Time{
		"gone":  clk.Now().Add(-8 * 24 * time.Hour),
		"jelly": clk.Now().Add(-2 * 24 * time.Hour),
	}}
	if err := st.Save(filepath.Join(cfg.Keys, "state.json")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := start(t, ctx, cfg)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(cfg.Sealed, "cut.sealed.tmp")) {
		t.Fatal("a cut-off write's .tmp left")
	}
	if exists(filepath.Join(cfg.Sealed, "gone.sealed")) {
		t.Fatal("a login missing 8 days kept")
	}
	for _, n := range []string{"jelly.sealed", "new.sealed"} {
		if !exists(filepath.Join(cfg.Sealed, n)) {
			t.Fatalf("%s deleted", n)
		}
	}
	got, err := missing.Load(filepath.Join(cfg.Keys, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Missing) != 1 || !got.Missing["new"].Equal(clk.Now()) {
		t.Fatalf("state: %v", got.Missing)
	}
}

func TestStartWithTheCardAwaySweepsNothing(t *testing.T) {
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	os.MkdirAll(cfg.Sealed, 0o700)
	os.WriteFile(filepath.Join(cfg.Sealed, "gone.sealed"), []byte("x"), 0o600)
	os.MkdirAll(cfg.Keys, 0o700)
	st := missing.State{Missing: map[string]time.Time{"gone": clk.Now().Add(-8 * 24 * time.Hour)}}
	st.Save(filepath.Join(cfg.Keys, "state.json"))
	os.WriteFile(cfg.Mounts, []byte("/dev/root / ext4 rw 0 0\n"), 0o644) // USB storage has the card

	ctx, cancel := context.WithCancel(context.Background())
	done := start(t, ctx, cfg)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(cfg.Sealed, "gone.sealed")) {
		t.Fatal("swept with the card away")
	}
	got, _ := missing.Load(filepath.Join(cfg.Keys, "state.json"))
	if _, ok := got.Missing["gone"]; !ok {
		t.Fatal("state changed with the card away")
	}
}

func TestStartWithACorruptStateKeepsGoing(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.Serve = asPlex
	os.MkdirAll(cfg.Keys, 0o700)
	os.WriteFile(filepath.Join(cfg.Keys, "state.json"), []byte("{not json"), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	done := start(t, ctx, cfg)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestABadKeyFileFails(t *testing.T) {
	cfg, _ := fixture(t)
	os.MkdirAll(cfg.Keys, 0o700)
	os.WriteFile(filepath.Join(cfg.Keys, "key"), []byte("short"), 0o600)
	if err := run(context.Background(), cfg); err == nil {
		t.Fatal("ran with a broken key file")
	}
}

func TestEraseAllMakesANewKey(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.Serve = asPlex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := start(t, ctx, cfg)
	ask(t, cfg.Socket, "put", []byte("s1"))
	old, _ := os.ReadFile(filepath.Join(cfg.Keys, "key"))
	page := func(op string) string {
		c, err := net.Dial("unix", cfg.Browse)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("Q2SPOT/1\n1\t" + op + "\n"))
		c.(*net.UnixConn).CloseWrite()
		b, _ := io.ReadAll(c)
		return string(b)
	}
	page("eraseall")
	if got := page("eraseall"); !strings.Contains(got, "All logins erased") {
		t.Fatalf("erase: %q", got)
	}
	now, _ := os.ReadFile(filepath.Join(cfg.Keys, "key"))
	if len(now) != 32 || bytes.Equal(old, now) {
		t.Fatal("no new key written")
	}
	if got := ask(t, cfg.Socket, "get", nil); got != "Q2VAULT/1\nnone\n" {
		t.Fatalf("get after erase: %q", got)
	}
	if got := ask(t, cfg.Socket, "put", []byte("s2")); got != "Q2VAULT/1\nok\n" {
		t.Fatalf("put after erase: %q", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The new key opens what was sealed after the erase.
	cfg2 := cfg
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := start(t, ctx2, cfg2)
	if got := ask(t, cfg.Socket, "get", nil); got != "Q2VAULT/1\nok\ns2" {
		t.Fatalf("get after restart: %q", got)
	}
	cancel2()
	<-done2
}

func TestNamesReadOncePerPageRequest(t *testing.T) {
	cfg, _ := fixture(t)
	os.MkdirAll(filepath.Join(cfg.Card, ".plex"), 0o755)
	os.WriteFile(filepath.Join(cfg.Card, ".plex", "q2app"), []byte("root=0\nname=Plex\n"), 0o644)
	os.MkdirAll(filepath.Join(cfg.Card, ".noname"), 0o755)
	os.WriteFile(filepath.Join(cfg.Card, ".noname", "q2app"), []byte("row=library\n"), 0o644)
	n := &names{card: cfg.Card}
	reads := 0
	n.read = func(card string) map[string]string { reads++; return readNames(card) }
	n.Stale()
	for range 3 {
		if got := n.Get(); got["plex"] != "Plex" || got["noname"] != "" {
			t.Fatalf("names: %v", got)
		}
	}
	if reads != 1 {
		t.Fatalf("%d reads for one request", reads)
	}
	n.Stale()
	n.Get()
	if reads != 2 {
		t.Fatalf("%d reads for two requests", reads)
	}
}

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cli([]string{"-version"}, &out, &errb); code != 0 || out.String() != "q2-v0.1\n" {
		t.Fatalf("code %d, out %q, err %q", code, out.String(), errb.String())
	}
	if code := cli([]string{"-nope"}, &out, &errb); code != 2 {
		t.Fatalf("bad flag: code %d", code)
	}
}

func TestKeyRandFallsBack(t *testing.T) {
	r := keyRand(filepath.Join(t.TempDir(), "no-hwrng"))
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil || bytes.Equal(b, make([]byte, 32)) {
		t.Fatalf("fallback: %v", err)
	}
	src := filepath.Join(t.TempDir(), "hwrng")
	os.WriteFile(src, bytes.Repeat([]byte{7}, 64), 0o600)
	if _, err := io.ReadFull(keyRand(src), b); err != nil || !bytes.Equal(b, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("hwrng not used: %v %x", err, b)
	}
}

// eraseFixture is a store with one login and its key file, for eraseAll.
func eraseFixture(t *testing.T) (*store.Store, config, [32]byte) {
	t.Helper()
	cfg, clk := fixture(t)
	key, err := store.LoadOrCreateKey(cfg.Keys, crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := &store.Store{Card: cfg.Card, Dir: cfg.Sealed, Mounts: cfg.Mounts, Master: key, Rand: crand.Reader, Now: clk.Now}
	if err := st.Put("plex", []byte("s1")); err != nil {
		t.Fatal(err)
	}
	return st, cfg, key
}

func keyFile(t *testing.T, cfg config) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg.Keys, "key"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEraseAllKeyWriteFailsChangesNothing(t *testing.T) {
	st, cfg, key := eraseFixture(t)
	if err := os.Chmod(cfg.Keys, 0o500); err != nil { // the new key can't be written
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cfg.Keys, 0o700) })
	if err := eraseAll(st, cfg.Keys, crand.Reader); err == nil {
		t.Fatal("no error when the key couldn't be written")
	}
	if !bytes.Equal(keyFile(t, cfg), key[:]) || st.Master != key {
		t.Fatal("key changed")
	}
	if got, err := st.Get("plex"); err != nil || string(got) != "s1" {
		t.Fatalf("login gone: %q %v", got, err)
	}
}

func TestEraseAllCardAwayKeepsTheOldKey(t *testing.T) {
	st, cfg, key := eraseFixture(t)
	orig := storeErase
	storeErase = func(st *store.Store, k [32]byte) error { // the card goes between the key and the erase
		os.WriteFile(cfg.Mounts, []byte("/dev/root / ext4 rw 0 0\n"), 0o644)
		return orig(st, k)
	}
	t.Cleanup(func() { storeErase = orig })
	if err := eraseAll(st, cfg.Keys, crand.Reader); !errors.Is(err, store.ErrCardAway) {
		t.Fatalf("err %v, want card away", err)
	}
	if !bytes.Equal(keyFile(t, cfg), key[:]) || st.Master != key {
		t.Fatal("old key not kept")
	}
}

func TestEraseAllCardAwayFirstWritesNothing(t *testing.T) {
	st, cfg, key := eraseFixture(t)
	os.WriteFile(cfg.Mounts, []byte("/dev/root / ext4 rw 0 0\n"), 0o644)
	if err := eraseAll(st, cfg.Keys, crand.Reader); !errors.Is(err, store.ErrCardAway) {
		t.Fatalf("err %v, want card away", err)
	}
	if !bytes.Equal(keyFile(t, cfg), key[:]) {
		t.Fatal("key file changed with the card away")
	}
}

func TestWanted(t *testing.T) {
	p := filepath.Join(t.TempDir(), "q2-vault.want")
	t0 := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	if wanted(p, t0) {
		t.Fatal("wanted with no file")
	}
	os.WriteFile(p, nil, 0o644)
	os.Chtimes(p, t0.Add(time.Second), t0.Add(time.Second))
	if !wanted(p, t0) {
		t.Fatal("a touch after the last tick not seen")
	}
	if wanted(p, t0.Add(time.Second)) || wanted(p, t0.Add(5*time.Second)) {
		t.Fatal("an old touch seen again")
	}
}

func TestRunStaysWhenTheLauncherWantsIt(t *testing.T) {
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	done := start(t, context.Background(), cfg)
	want := filepath.Join(cfg.Tmp, "q2-vault.want")
	clk.Add(50 * time.Second)
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(want, nil, 0o644) // an app's start ran the launcher again
	os.Chtimes(want, clk.Now().Add(time.Second), clk.Now().Add(time.Second))
	clk.Add(time.Second)
	time.Sleep(50 * time.Millisecond)
	clk.Add(10 * time.Second) // 61 s: the page's minute is over, the touch 10 s old
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("closed though just wanted: %v", err)
	default:
	}
	clk.Add(30 * time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running 30 s after the touch")
	}
}

func TestRunFailsWithoutItsPage(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.Serve = asPlex
	cfg.Browse = filepath.Join(filepath.Dir(cfg.Browse), "no-such-dir", "b.sock")
	orig := wipe
	wiped := false
	wipe = func(k *[32]byte) { orig(k); wiped = true }
	t.Cleanup(func() { wipe = orig })
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), cfg) }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("ran without its page")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running without its page")
	}
	if !wiped || exists(cfg.Socket) {
		t.Fatalf("not closed cleanly: wiped %v, socket left %v", wiped, exists(cfg.Socket))
	}
}

func TestRunNeverIdleExitsWithoutNeeds(t *testing.T) {
	// Firmware without needs= restarts nothing that closes: the Vault stays.
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	os.Remove(cfg.Caps)
	done := start(t, context.Background(), cfg)
	for range 3 {
		clk.Add(10 * time.Minute)
		time.Sleep(50 * time.Millisecond)
	}
	os.WriteFile(cfg.Caps, []byte("art now window\n"), 0o644) // other words only
	clk.Add(10 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("closed on firmware without needs=: %v", err)
	default:
	}
	// The caps are read again at each idle decision.
	os.WriteFile(cfg.Caps, []byte("art needs window\n"), 0o644)
	clk.Add(time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running once the firmware has needs=")
	}
}

func TestRunStaysForAnAppThatAskedThisRun(t *testing.T) {
	// plex has no needs=vault and no sealed file yet (signing in for the first
	// time); it asked, so it counts as an app that uses the Vault until it stops.
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	var mu sync.Mutex
	plexUp := true
	cfg.running = func(_, id string) bool { mu.Lock(); defer mu.Unlock(); return id == "plex" && plexUp }
	done := start(t, context.Background(), cfg)
	if got := ask(t, cfg.Socket, "get", nil); got != "Q2VAULT/1\nnone\n" {
		t.Fatalf("get: %q", got)
	}
	for range 3 {
		clk.Add(40 * time.Second)
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("closed while an app that asked runs: %v", err)
	default:
	}
	mu.Lock()
	plexUp = false
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	clk.Add(61 * time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running after the app stopped")
	}
}

func TestFirmwareHasTrustsOnlyRootsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "caps")
	os.WriteFile(p, []byte("art needs\n"), 0o644)
	no := func(os.FileInfo) bool { return false }
	yes := func(os.FileInfo) bool { return true }
	if firmwareHas(p, "needs", no) { // an app's file: no needs
		t.Fatal("trusted a caps file not owned by root")
	}
	if !firmwareHas(p, "needs", yes) {
		t.Fatal("root's caps file not read")
	}
	if firmwareHas(p, "needs", ownedByRoot) { // the test's own file, for real
		t.Fatal("trusted a file the test (not root) owns")
	}
	// A link (to root's file, even) or a folder is not trusted.
	l := filepath.Join(dir, "link")
	os.Symlink(p, l)
	if firmwareHas(l, "needs", yes) {
		t.Fatal("followed a link")
	}
	if firmwareHas(dir, "needs", yes) {
		t.Fatal("read a folder")
	}
}

func TestRunStaysWhenCapsAreNotRoots(t *testing.T) {
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	cfg.capsOwner = func(os.FileInfo) bool { return false } // an app wrote it
	done := start(t, context.Background(), cfg)
	clk.Add(10 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("closed on caps an app could have written: %v", err)
	default:
	}
}

func TestFirmwareHas(t *testing.T) {
	p := filepath.Join(t.TempDir(), "caps")
	yes := func(os.FileInfo) bool { return true }
	if firmwareHas(p, "needs", yes) {
		t.Fatal("no file has needs")
	}
	for text, want := range map[string]bool{
		"needs\n": true, "art needs now\n": true, "art\tneeds": true, "needsx art": false,
		"art now": false, "": false, "xneeds": false,
	} {
		os.WriteFile(p, []byte(text), 0o644)
		if got := firmwareHas(p, "needs", yes); got != want {
			t.Errorf("%q: %v, want %v", text, got, want)
		}
	}
}

func TestRunSetsAsideAFolderAtThePagePath(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.Serve = asPlex
	os.MkdirAll(filepath.Join(cfg.Browse, "inside"), 0o755)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()
	waitFor(t, "the page's socket in place of the folder", func() bool {
		fi, err := os.Lstat(cfg.Browse)
		return err == nil && fi.Mode()&os.ModeSocket != 0
	})
	if !exists(filepath.Join(cfg.Browse+".bad."+strconv.Itoa(os.Getpid()), "inside")) {
		t.Fatal("folder not set aside")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSweepKeepsQ2Pod(t *testing.T) {
	cfg, clk := fixture(t)
	cfg.Serve = asPlex
	os.MkdirAll(cfg.Sealed, 0o700)
	os.WriteFile(filepath.Join(cfg.Sealed, "q2pod.sealed"), []byte("x"), 0o600)
	os.MkdirAll(cfg.Keys, 0o700)
	st := missing.State{Missing: map[string]time.Time{"q2pod": clk.Now().Add(-30 * 24 * time.Hour)}}
	if err := st.Save(filepath.Join(cfg.Keys, "state.json")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := start(t, ctx, cfg)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(cfg.Sealed, "q2pod.sealed")) {
		t.Fatal("Q2 Pod's own login swept: it has no card folder")
	}
	got, _ := missing.Load(filepath.Join(cfg.Keys, "state.json"))
	if _, ok := got.Missing["q2pod"]; ok {
		t.Fatal("q2pod still counted as missing")
	}
}

func TestNamesQ2Pod(t *testing.T) {
	if got := readNames(t.TempDir())["q2pod"]; got != "Q2 Pod (scrobbling)" {
		t.Fatalf("q2pod's name %q", got)
	}
}
