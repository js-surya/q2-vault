package seal

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"testing"
)

var master = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

func mustSeal(t *testing.T, id string, secret []byte) []byte {
	t.Helper()
	b, err := Seal(AppKey(master, id), id, secret, crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	blob := mustSeal(t, "plex", []byte("tok"))
	got, err := Open(AppKey(master, "plex"), "plex", blob)
	if err != nil || string(got) != "tok" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestFormat(t *testing.T) {
	s := []byte("hello secret")
	blob := mustSeal(t, "plex", s)
	if !bytes.HasPrefix(blob, []byte("Q2VT\x01")) {
		t.Fatalf("bad header %q", blob[:5])
	}
	if len(blob) != 5+24+len(s)+16 {
		t.Fatalf("len %d", len(blob))
	}
}

func TestKeysDifferPerApp(t *testing.T) {
	if AppKey(master, "plex") == AppKey(master, "jellyfin") {
		t.Fatal("keys equal")
	}
}

func TestWrongKey(t *testing.T) {
	blob := mustSeal(t, "plex", []byte("tok"))
	other := master
	other[0] ^= 1
	if _, err := Open(AppKey(other, "plex"), "plex", blob); !errors.Is(err, ErrBad) {
		t.Fatalf("got %v", err)
	}
}

func TestChangedByte(t *testing.T) {
	blob := mustSeal(t, "plex", []byte("tok"))
	blob[5+24] ^= 1
	if _, err := Open(AppKey(master, "plex"), "plex", blob); !errors.Is(err, ErrBad) {
		t.Fatalf("got %v", err)
	}
}

func TestRenamed(t *testing.T) {
	blob := mustSeal(t, "plex", []byte("tok"))
	for _, k := range [][32]byte{AppKey(master, "jellyfin"), AppKey(master, "plex")} {
		if _, err := Open(k, "jellyfin", blob); !errors.Is(err, ErrBad) {
			t.Fatalf("got %v", err)
		}
	}
}

func TestSizes(t *testing.T) {
	k := AppKey(master, "plex")
	if _, err := Seal(k, "plex", make([]byte, 16384), crand.Reader); err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(k, "plex", make([]byte, 16385), crand.Reader); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if _, err := Seal(k, "plex", nil, crand.Reader); !errors.Is(err, ErrEmpty) {
		t.Fatalf("got %v", err)
	}
	blob := mustSeal(t, "plex", []byte("tok"))
	if _, err := Open(k, "plex", blob[:44]); !errors.Is(err, ErrBad) {
		t.Fatalf("trunc: %v", err)
	}
	bad := append([]byte(nil), blob...)
	bad[0] = 'X'
	if _, err := Open(k, "plex", bad); !errors.Is(err, ErrBad) {
		t.Fatalf("magic: %v", err)
	}
	bad = append([]byte(nil), blob...)
	bad[4] = 2
	if _, err := Open(k, "plex", bad); !errors.Is(err, ErrBad) {
		t.Fatalf("version: %v", err)
	}
}
