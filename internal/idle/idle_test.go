package idle

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUsersFromNeedsAndSealed(t *testing.T) {
	card, sealed := t.TempDir(), t.TempDir()
	write(t, filepath.Join(card, ".one", "q2app"), "name=One\nneeds=vault\n")
	write(t, filepath.Join(card, ".two", "q2app"), "needs=a,vault\r\n")
	write(t, filepath.Join(card, ".three", "q2app"), "needs=vaults\n")
	write(t, filepath.Join(card, ".vault", "q2app"), "needs=vault\n")
	write(t, filepath.Join(card, ".spaced", "q2app"), "needs= a , vault \r\n")
	write(t, filepath.Join(card, ".fifth", "q2app"), "needs=a,b,c,d,vault\n")
	write(t, filepath.Join(card, ".bad_id", "q2app"), "needs=vault\n")
	write(t, filepath.Join(card, ".invalid", "q2app"), "needs=A!,vault\n")
	if err := os.MkdirAll(filepath.Join(card, ".nofile"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(sealed, "old.sealed"), "x")
	write(t, filepath.Join(sealed, "vault.sealed"), "x")
	write(t, filepath.Join(sealed, "notes.txt"), "x")

	got := Users(card, sealed)
	sort.Strings(got)
	want := []string{"invalid", "old", "one", "spaced", "two"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := Users(filepath.Join(card, "missing"), filepath.Join(sealed, "missing")); len(got) != 0 {
		t.Fatalf("missing dirs: %v", got)
	}
}

func TestRunning(t *testing.T) {
	tmp, proc := t.TempDir(), t.TempDir()
	old := procRoot
	procRoot = proc
	defer func() { procRoot = old }()

	write(t, filepath.Join(tmp, "q2-live"), "4242\n")
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	write(t, filepath.Join(tmp, "q2-dead"), "999")
	write(t, filepath.Join(tmp, "q2-junk"), "abc")
	write(t, filepath.Join(tmp, "q2-empty"), "")
	write(t, filepath.Join(tmp, "q2-one"), "1")
	os.MkdirAll(filepath.Join(proc, "1"), 0o755)
	for id, want := range map[string]bool{"live": true, "dead": false, "junk": false, "empty": false, "one": false, "none": false} {
		if got := Running(tmp, id); got != want {
			t.Errorf("%s: got %v want %v", id, got, want)
		}
	}
}

func TestIdle(t *testing.T) {
	now := time.Unix(1000, 0)
	tr := &Tracker{Now: func() time.Time { return now }}
	if tr.Idle() {
		t.Fatal("new tracker is idle")
	}
	now = now.Add(29 * time.Second)
	if tr.Idle() {
		t.Fatal("29s idle")
	}
	now = now.Add(time.Second)
	// seen 30s ago, page = creation 30s ago (counts as just seen): not yet 60s
	tr2 := &Tracker{Now: func() time.Time { return now }}
	tr2.Seen()
	tr2.Page()
	now = now.Add(30 * time.Second)
	if tr2.Idle() {
		t.Fatal("page 30s ago must keep it")
	}
	now = now.Add(29 * time.Second)
	if tr2.Idle() {
		t.Fatal("page 59s ago must keep it")
	}
	now = now.Add(time.Second)
	if !tr2.Idle() {
		t.Fatal("page 60s ago, seen 90s ago: idle")
	}
	tr2.Seen()
	if tr2.Idle() {
		t.Fatal("seen resets")
	}
}

func TestIdleThirtySeconds(t *testing.T) {
	now := time.Unix(1000, 0)
	tr := &Tracker{Now: func() time.Time { return now }}
	tr.Seen()
	tr.Page()
	now = now.Add(60 * time.Second)
	if !tr.Idle() {
		t.Fatal("60s: idle")
	}
	tr.Page()
	now = now.Add(30 * time.Second)
	if tr.Idle() {
		t.Fatal("page 30s ago keeps")
	}
	// Seen only 30s ago, page 90s ago
	tr.Seen()
	now = now.Add(29 * time.Second)
	tr.page = now.Add(-90 * time.Second)
	if tr.Idle() {
		t.Fatal("seen 29s ago")
	}
	now = now.Add(time.Second)
	if !tr.Idle() {
		t.Fatal("seen 30s ago")
	}
}

func TestTrackerRace(t *testing.T) {
	tr := &Tracker{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tr.Seen()
				tr.Page()
				tr.Idle()
			}
		}()
	}
	wg.Wait()
}
