package missing

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func gone(string) bool { return false }

func TestFirstSeenNotRemoved(t *testing.T) {
	s := State{}
	rm := Sweep(&s, []string{"a"}, gone, t0)
	if len(rm) != 0 {
		t.Fatalf("removed %v", rm)
	}
	if got := s.Missing["a"]; !got.Equal(t0) {
		t.Fatalf("first seen = %v", got)
	}
	// a later sweep must not move the first-seen time
	Sweep(&s, []string{"a"}, gone, t0.Add(time.Hour))
	if !s.Missing["a"].Equal(t0) {
		t.Fatal("first-seen time moved")
	}
}

func TestRemovedAfterSevenDays(t *testing.T) {
	s := State{Missing: map[string]time.Time{"a": t0}}
	if rm := Sweep(&s, []string{"a"}, gone, t0.Add(6*24*time.Hour+23*time.Hour)); len(rm) != 0 {
		t.Fatalf("removed early: %v", rm)
	}
	rm := Sweep(&s, []string{"a"}, gone, t0.Add(7*24*time.Hour))
	if !reflect.DeepEqual(rm, []string{"a"}) {
		t.Fatalf("remove = %v", rm)
	}
	if _, ok := s.Missing["a"]; ok {
		t.Fatal("removed id still listed")
	}
}

func TestBackIsForgotten(t *testing.T) {
	s := State{Missing: map[string]time.Time{"a": t0, "b": t0, "c": t0}}
	installed := func(id string) bool { return id == "a" }
	// c is no longer a stored login at all
	rm := Sweep(&s, []string{"a", "b"}, installed, t0.Add(30*24*time.Hour))
	sort.Strings(rm)
	if !reflect.DeepEqual(rm, []string{"b"}) {
		t.Fatalf("remove = %v", rm)
	}
	if len(s.Missing) != 0 {
		t.Fatalf("Missing = %v", s.Missing)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s := State{Missing: map[string]time.Time{"a": t0}}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	got, err := Load(p)
	if err != nil || !got.Missing["a"].Equal(t0) || len(got.Missing) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp left behind")
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || s.Missing == nil || len(s.Missing) != 0 {
		t.Fatalf("%v %v", s, err)
	}
}

func TestLoadCorruptReturnsErrorAndUsableEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(p, []byte("{not json"), 0o600)
	s, err := Load(p)
	if err == nil {
		t.Fatal("want error")
	}
	if s.Missing == nil || len(s.Missing) != 0 {
		t.Fatal("state must be empty and usable")
	}
	Sweep(&s, []string{"a"}, gone, t0) // must not panic
	// unreadable: a directory where the file should be
	d := t.TempDir()
	if _, err := Load(d); err == nil {
		t.Fatal("want error for unreadable")
	}
	// JSON null
	os.WriteFile(p, []byte("null"), 0o600)
	s, err = Load(p)
	if err != nil || s.Missing == nil {
		t.Fatalf("null: %v %v", s, err)
	}
}

func TestClockBeforeFloorChangesNothing(t *testing.T) {
	s := State{Missing: map[string]time.Time{"a": t0, "gone": t0}}
	rm := Sweep(&s, []string{"a", "b"}, gone, time.Unix(0, 0))
	if rm != nil || len(s.Missing) != 2 || !s.Missing["a"].Equal(t0) || !s.Missing["gone"].Equal(t0) {
		t.Fatalf("rm=%v state=%v", rm, s.Missing)
	}
}

func TestImplausibleStoredTimeRestamped(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s := State{Missing: map[string]time.Time{"a": time.Unix(0, 0).UTC(), "z": {}}}
	rm := Sweep(&s, []string{"a", "z"}, gone, now)
	if len(rm) != 0 || !s.Missing["a"].Equal(now) || !s.Missing["z"].Equal(now) {
		t.Fatalf("rm=%v state=%v", rm, s.Missing)
	}
}

func TestBackwardsClockRemovesNothing(t *testing.T) {
	s := State{Missing: map[string]time.Time{"a": t0}}
	rm := Sweep(&s, []string{"a"}, gone, t0.Add(-time.Hour))
	if len(rm) != 0 || !s.Missing["a"].Equal(t0) {
		t.Fatalf("rm=%v state=%v", rm, s.Missing)
	}
}

func TestDuplicateIDsReturnedOnce(t *testing.T) {
	s := State{Missing: map[string]time.Time{"a": t0}}
	rm := Sweep(&s, []string{"a", "a"}, gone, t0.Add(8*24*time.Hour))
	if !reflect.DeepEqual(rm, []string{"a"}) {
		t.Fatalf("rm=%v", rm)
	}
}
