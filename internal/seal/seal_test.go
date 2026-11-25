package seal

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
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
	fixed := bytes.Repeat([]byte{7}, 24)
	blob, err := Seal(AppKey(master, "plex"), "plex", s, bytes.NewReader(fixed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[5:29], fixed) {
		t.Fatal("nonce not from rand")
	}
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
	for _, i := range []int{5 + 24, 5, len(blob) - 1} {
		c := append([]byte(nil), blob...)
		c[i] ^= 1
		if _, err := Open(AppKey(master, "plex"), "plex", c); !errors.Is(err, ErrBad) {
			t.Fatalf("byte %d: got %v", i, err)
		}
	}
}

func TestKnownAnswer(t *testing.T) {
	h, _ := blake2b.New256(master[:])
	h.Write([]byte("q2pod-vault/v1/plex"))
	var want [32]byte
	h.Sum(want[:0])
	if AppKey(master, "plex") != want {
		t.Fatal("derivation changed")
	}
}

func TestShortRand(t *testing.T) {
	b, err := Seal(AppKey(master, "plex"), "plex", []byte("x"), bytes.NewReader(make([]byte, 10)))
	if err == nil || b != nil {
		t.Fatalf("got %v, %v", b, err)
	}
}

func TestOpenBounds(t *testing.T) {
	k := AppKey(master, "plex")
	if _, err := Open(k, "plex", make([]byte, MaxBlob+1)); !errors.Is(err, ErrBad) {
		t.Fatalf("big: %v", err)
	}
	aead, _ := chacha20poly1305.NewX(k[:])
	nonce := make([]byte, 24)
	blob := append([]byte("Q2VT\x01"), nonce...)
	blob = aead.Seal(blob, nonce, nil, []byte("q2pod-vault/v1/plex"))
	if len(blob) != 45 {
		t.Fatalf("len %d", len(blob))
	}
	if _, err := Open(k, "plex", blob); !errors.Is(err, ErrBad) {
		t.Fatalf("empty: %v", err)
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
