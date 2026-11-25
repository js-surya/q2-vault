// Package seal derives per-app keys and seals an app's secret into the
// Q2VT file format: "Q2VT" | 0x01 | 24-byte nonce | XChaCha20-Poly1305.
package seal

import (
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// MaxSecret is the largest secret that can be sealed.
const MaxSecret = 16384

// MaxBlob is the largest sealed blob Open accepts.
const MaxBlob = 5 + 24 + MaxSecret + 16

var (
	ErrTooLarge = errors.New("seal: secret too large")
	ErrEmpty    = errors.New("seal: secret empty")
	ErrBad      = errors.New("seal: sealed data does not open")
)

const (
	prefix  = "q2pod-vault/v1/"
	magic   = "Q2VT"
	version = 1
	header  = len(magic) + 1
)

// AppKey returns BLAKE2b-256 keyed with master over "q2pod-vault/v1/"+id.
func AppKey(master [32]byte, id string) [32]byte {
	h, err := blake2b.New256(master[:])
	if err != nil {
		panic(err) // key length is fixed and valid
	}
	h.Write([]byte(prefix + id))
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Seal encrypts secret for the app id, drawing the nonce from rand.
func Seal(key [32]byte, id string, secret []byte, rand io.Reader) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmpty
	}
	if len(secret) > MaxSecret {
		return nil, ErrTooLarge
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	blob := make([]byte, header+aead.NonceSize(), header+aead.NonceSize()+len(secret)+aead.Overhead())
	copy(blob, magic)
	blob[len(magic)] = version
	if _, err := io.ReadFull(rand, blob[header:]); err != nil {
		return nil, err
	}
	nonce := append([]byte(nil), blob[header:]...)
	return aead.Seal(blob, nonce, secret, []byte(prefix+id)), nil
}

// Open decrypts blob for the app id; any failure is ErrBad.
func Open(key [32]byte, id string, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, ErrBad
	}
	if len(blob) < header+aead.NonceSize()+1+aead.Overhead() || len(blob) > MaxBlob ||
		string(blob[:len(magic)]) != magic || blob[len(magic)] != version {
		return nil, ErrBad
	}
	nonce := blob[header : header+aead.NonceSize()]
	pt, err := aead.Open(nil, nonce, blob[header+aead.NonceSize():], []byte(prefix+id))
	if err != nil {
		return nil, ErrBad
	}
	return pt, nil
}
