package proto

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// withSystem points systemExe at a temp file standing in for /release/bin/demo.
func withSystem(t *testing.T) string {
	t.Helper()
	old := systemExe
	systemExe = filepath.Join(t.TempDir(), "release", "bin", "demo")
	touch(t, systemExe)
	t.Cleanup(func() { systemExe = old })
	return systemExe
}

func status(t *testing.T, root string, pid int, uid string) {
	t.Helper()
	line := "Name:\tdemo\nUid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\nGid:\t0\t0\t0\t0\n"
	if err := os.WriteFile(filepath.Join(root, strconv.Itoa(pid), "status"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAppIDSystemCaller(t *testing.T) {
	withCard(t)
	exe := withSystem(t)
	root := fakeProc(t, 100, exe)
	status(t, root, 100, "0")
	id, err := AppID(root, 100)
	if err != nil || id != "q2pod" {
		t.Fatalf("got %q, %v; want q2pod", id, err)
	}
}

func TestAppIDSystemCallerRefused(t *testing.T) {
	withCard(t)
	exe := withSystem(t)
	cases := map[string]func() (string, int){
		"not root": func() (string, int) {
			root := fakeProc(t, 100, exe)
			status(t, root, 100, "1000")
			return root, 100
		},
		"no status": func() (string, int) {
			return fakeProc(t, 100, exe), 100
		},
		"other namespace": func() (string, int) {
			root := fakeProc(t, 100, exe)
			status(t, root, 100, "0")
			ns := filepath.Join(root, "100", "ns", "mnt")
			os.Remove(ns)
			os.Symlink("mnt:[2]", ns)
			return root, 100
		},
		"deleted": func() (string, int) {
			root := fakeProc(t, 100, exe+" (deleted)")
			status(t, root, 100, "0")
			return root, 100
		},
		"elsewhere": func() (string, int) {
			root := fakeProc(t, 100, "/tmp/demo")
			status(t, root, 100, "0")
			return root, 100
		},
	}
	for name, setup := range cases {
		root, pid := setup()
		if id, err := AppID(root, pid); err == nil {
			t.Errorf("%s: accepted as %q", name, id)
		}
	}
}

func TestAppIDSystemCallerOtherInode(t *testing.T) {
	withCard(t)
	exe := withSystem(t)
	root := fakeProc(t, 100, exe)
	status(t, root, 100, "0")
	other := filepath.Join(t.TempDir(), "other")
	touch(t, other)
	old := exeStat
	t.Cleanup(func() { exeStat = old })
	exeStat = func(string) (os.FileInfo, error) { return os.Stat(other) }
	if id, err := AppID(root, 100); err == nil {
		t.Fatalf("a different file at the path accepted as %q", id)
	}
}

func TestAppIDReservedFolderRefused(t *testing.T) {
	R := withCard(t)
	touch(t, R+"/.q2pod/q2-q2pod")
	root := fakeProc(t, 100, R+"/.q2pod/q2-q2pod")
	if id, err := AppID(root, 100); err == nil {
		t.Fatalf("a card app in .q2pod accepted as %q", id)
	}
}
