// Adapted from q2-tailscale's cmd/q2-tailscale/remove_test.go (same author, MIT).

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// removeFixture is a card (mounted per mounts) with the app's folder and the sealed logins on it, and
// the key in keys.
func removeFixture(t *testing.T, mounted bool) (dir, keys, sealed, mounts string) {
	t.Helper()
	root := t.TempDir()
	card := filepath.Join(root, "mmc")
	dir = filepath.Join(card, ".vault")
	sealed = filepath.Join(card, ".q2vault")
	keys = filepath.Join(root, "data", "apps", "vault")
	for _, d := range []string{dir, keys, sealed} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(keys, "key"), filepath.Join(sealed, "plex.sealed")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mounts = filepath.Join(root, "mounts")
	line := "/dev/root / ext4 rw 0 0\n"
	if mounted {
		line += "/dev/mmcblk0p1 " + card + " exfat rw 0 0\n"
	}
	if err := os.WriteFile(mounts, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, keys, sealed, mounts
}

func TestRemoveTakesKeyAndLoginsToo(t *testing.T) {
	dir, keys, sealed, mounts := removeFixture(t, true)
	cmd := watchRemove(dir, keys, sealed, mounts, 40, "0.05")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // the App Store deletes the folder after the app has stopped
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if exists(keys) || exists(sealed) {
		t.Fatalf("left behind after Remove: key %v, logins %v", exists(keys), exists(sealed))
	}
}

func TestAStopKeepsKeyAndLogins(t *testing.T) {
	dir, keys, sealed, mounts := removeFixture(t, true)
	if err := watchRemove(dir, keys, sealed, mounts, 3, "0.05").Run(); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(keys, "key")) || !exists(filepath.Join(sealed, "plex.sealed")) {
		t.Fatal("deleted on an ordinary stop")
	}
}

func TestACardTakenOutKeepsTheKey(t *testing.T) {
	dir, keys, sealed, mounts := removeFixture(t, false)
	if err := os.RemoveAll(dir); err != nil { // the folder is gone with the card, not removed
		t.Fatal(err)
	}
	if err := watchRemove(dir, keys, sealed, mounts, 3, "0.05").Run(); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(keys, "key")) {
		t.Fatal("key deleted with the card out")
	}
}

func TestNoWatchOnAShallowOrStrayPath(t *testing.T) {
	for _, keys := range []string{"", "/", "/mnt", "/mnt/data", "relative/apps/vault"} {
		if watchRemove("/mnt/mmc/.vault", keys, "/mnt/mmc/.q2vault", "/proc/mounts", 1, "1") != nil {
			t.Errorf("watch for keys %q", keys)
		}
	}
	for _, sealed := range []string{"", "/", "/mnt", "/mnt/mmc", "/mnt/mmc/.vault", "/mnt/data/.q2vault", "/mnt/mmc/x/.q2vault", "mmc/.q2vault"} {
		if watchRemove("/mnt/mmc/.vault", "/mnt/data/apps/vault", sealed, "/proc/mounts", 1, "1") != nil {
			t.Errorf("watch for sealed %q", sealed)
		}
	}
	if watchRemove("/", "/mnt/data/apps/vault", "/.q2vault", "/proc/mounts", 1, "1") != nil {
		t.Error("watch for an app folder that is the root")
	}
	if watchRemove("/mnt/mmc/.vault", "/mnt/data/apps/vault", "/mnt/mmc/.q2vault", "/proc/mounts", 1, "1") == nil {
		t.Error("no watch for the real paths")
	}
}
