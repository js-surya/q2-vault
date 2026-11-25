package store

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"q2-vault/internal/seal"
)

func newStore(t *testing.T, mounted bool) *Store {
	t.Helper()
	root := t.TempDir()
	card := filepath.Join(root, "mmc")
	if err := os.Mkdir(card, 0o755); err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(root, "mounts")
	line := "rootfs / ext4 rw 0 0\n"
	if mounted {
		line += "/dev/mmcblk0p1 " + card + " vfat rw 0 0\n"
	}
	if err := os.WriteFile(mounts, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	var m [32]byte
	rand.Read(m[:])
	return &Store{Card: card, Dir: filepath.Join(card, ".q2vault"), Mounts: mounts,
		Master: m, Rand: rand.Reader, Now: time.Now}
}

func TestKeyCreatedOnceAndKept(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	k1, err := LoadOrCreateKey(dir, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	di, _ := os.Stat(dir)
	fi, _ := os.Stat(filepath.Join(dir, "key"))
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("modes %v %v", di.Mode().Perm(), fi.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(dir, rand.Reader)
	if err != nil || k1 != k2 {
		t.Fatalf("second call differs: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "key"), make([]byte, 31), 0o600)
	if _, err := LoadOrCreateKey(dir, rand.Reader); err == nil {
		t.Fatal("31-byte key accepted")
	}
}

func TestPutGetDelete(t *testing.T) {
	s := newStore(t, true)
	if err := s.Put("plex", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("plex")
	if err != nil || string(got) != "tok" {
		t.Fatalf("%q %v", got, err)
	}
	if err := s.Delete("plex"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("plex"); !errors.Is(err, ErrNone) {
		t.Fatalf("want ErrNone, got %v", err)
	}
	if err := s.Delete("plex"); err != nil {
		t.Fatalf("delete of nothing: %v", err)
	}
}

func TestPutErrorsFromSeal(t *testing.T) {
	s := newStore(t, true)
	os.Mkdir(s.Dir, 0o700)
	if err := s.Put("a", nil); !errors.Is(err, seal.ErrEmpty) {
		t.Fatalf("got %v", err)
	}
	if err := s.Put("a", make([]byte, seal.MaxSecret+1)); !errors.Is(err, seal.ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if es, _ := os.ReadDir(s.Dir); len(es) != 0 {
		t.Fatalf("files left: %v", es)
	}
}

func TestBadID(t *testing.T) {
	s := newStore(t, true)
	for _, id := range []string{"", "../x", "A", "a.b", "abcdefghijklmnop"} {
		if err := s.Put(id, []byte("x")); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
}

func TestCardAway(t *testing.T) {
	s := newStore(t, false)
	if err := s.Put("plex", []byte("x")); !errors.Is(err, ErrCardAway) {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.Get("plex"); !errors.Is(err, ErrCardAway) {
		t.Fatalf("Get: %v", err)
	}
	if err := s.Delete("plex"); !errors.Is(err, ErrCardAway) {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.List(); !errors.Is(err, ErrCardAway) {
		t.Fatalf("List: %v", err)
	}
	if err := s.EraseAll([32]byte{1}); !errors.Is(err, ErrCardAway) {
		t.Fatalf("EraseAll: %v", err)
	}
	if err := s.Clean(); !errors.Is(err, ErrCardAway) {
		t.Fatalf("Clean: %v", err)
	}
	es, _ := os.ReadDir(s.Card)
	if len(es) != 0 {
		t.Fatalf("created under Card: %v", es)
	}
}

func TestUnreadableSetAside(t *testing.T) {
	s := newStore(t, true)
	if err := s.Put("plex", []byte("x")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.Dir, "plex.sealed")
	os.WriteFile(p, []byte("garbage garbage garbage garbage garbage garbage"), 0o600)
	if _, err := s.Get("plex"); !errors.Is(err, ErrNone) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(p + ".bad"); err != nil {
		t.Fatal(".bad missing")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal(".sealed still there")
	}
}

func TestConcurrentPuts(t *testing.T) {
	s := newStore(t, true)
	vals := map[string]bool{}
	var list []string
	for i := 0; i < 20; i++ {
		v := fmt.Sprintf("value-%02d-%s", i, bytes.Repeat([]byte("z"), 500))
		vals[v] = true
		list = append(list, v)
	}
	stop := make(chan struct{})
	var rg sync.WaitGroup
	for r := 0; r < 4; r++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, err := s.Get("plex")
				if errors.Is(err, ErrNone) {
					continue
				}
				if err != nil || !vals[string(got)] {
					t.Errorf("Get: %v (known value=%v)", err, vals[string(got)])
					return
				}
			}
		}()
	}
	var wg sync.WaitGroup
	for _, v := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Put("plex", []byte(v)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(stop)
	rg.Wait()
	got, err := s.Get("plex")
	if err != nil || !vals[string(got)] {
		t.Fatalf("final value not one written: %v", err)
	}
	tmps, _ := filepath.Glob(filepath.Join(s.Dir, "*.tmp"))
	if len(tmps) != 0 {
		t.Fatalf("tmp left: %v", tmps)
	}
}

func TestCleanAndListIgnoreTmp(t *testing.T) {
	s := newStore(t, true)
	s.Put("jf", []byte("x"))
	tmp := filepath.Join(s.Dir, "plex.sealed.tmp")
	os.WriteFile(tmp, []byte("half"), 0o600)
	es, err := s.List()
	if err != nil || len(es) != 1 || es[0].ID != "jf" || es[0].Saved.IsZero() {
		t.Fatalf("%v %v", es, err)
	}
	if _, err := s.Get("plex"); !errors.Is(err, ErrNone) {
		t.Fatalf("Get saw tmp: %v", err)
	}
	if err := s.Clean(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp not removed")
	}
	if _, err := s.Get("jf"); err != nil {
		t.Fatal("Clean removed a real file")
	}
}

func TestEraseAll(t *testing.T) {
	s := newStore(t, true)
	s.Put("a", []byte("1"))
	s.Put("b", []byte("2"))
	k2 := [32]byte{9, 9, 9}
	if err := s.EraseAll(k2); err != nil {
		t.Fatal(err)
	}
	if es, _ := s.List(); len(es) != 0 {
		t.Fatalf("list: %v", es)
	}
	if s.Master != k2 {
		t.Fatal("master not replaced")
	}
	if err := s.Put("a", []byte("3")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("a"); err != nil || string(got) != "3" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestEraseAllTriesEverything(t *testing.T) {
	s := newStore(t, true)
	s.Put("a", []byte("1"))
	s.Put("c", []byte("3"))
	stuck := filepath.Join(s.Dir, "b.sealed")
	os.MkdirAll(filepath.Join(stuck, "inner"), 0o700)
	k2 := [32]byte{7}
	if err := s.EraseAll(k2); err == nil {
		t.Fatal("want an error for the stuck entry")
	}
	for _, id := range []string{"a", "c"} {
		if _, err := os.Stat(filepath.Join(s.Dir, id+".sealed")); !os.IsNotExist(err) {
			t.Fatalf("%s survived", id)
		}
	}
	if s.Master != k2 {
		t.Fatal("new master not adopted")
	}
}

func TestKeyPermissionsFixedAndZeroRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	k1, _ := LoadOrCreateKey(dir, rand.Reader)
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Join(dir, "key"), 0o644)
	k2, err := LoadOrCreateKey(dir, rand.Reader)
	if err != nil || k1 != k2 {
		t.Fatal(err)
	}
	di, _ := os.Stat(dir)
	fi, _ := os.Stat(filepath.Join(dir, "key"))
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("modes %v %v", di.Mode().Perm(), fi.Mode().Perm())
	}
	os.WriteFile(filepath.Join(dir, "key"), make([]byte, 32), 0o600)
	if _, err := LoadOrCreateKey(dir, rand.Reader); err == nil {
		t.Fatal("all-zero key accepted")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "key")); !bytes.Equal(b, make([]byte, 32)) {
		t.Fatal("zero key was overwritten")
	}
}

func TestCutOffWriteKeepsOldFile(t *testing.T) {
	s := newStore(t, true)
	if err := s.Put("plex", []byte("old")); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(s.Dir, "plex.sealed.tmp"), 0o700)
	if err := s.Put("plex", []byte("new")); err == nil {
		t.Fatal("Put should fail")
	}
	got, err := s.Get("plex")
	if err != nil || string(got) != "old" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestPutFolderIs0700UnderNarrowUmask(t *testing.T) {
	s := newStore(t, true)
	old := syscall.Umask(0o111)
	err := s.Put("plex", []byte("tok"))
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode %v %v", fi.Mode().Perm(), err)
	}
}
