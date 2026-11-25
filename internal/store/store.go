package store

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"q2-vault/internal/seal"
)

var (
	ErrNone     = errors.New("store: nothing saved for this app")
	ErrCardAway = errors.New("store: the card is not mounted")
	ErrBadID    = errors.New("store: bad app id")
)

var idRe = regexp.MustCompile(`^[a-z0-9-]{1,15}$`)

// Entry is one saved login: the app id and when it was saved.
type Entry struct {
	ID    string
	Saved time.Time
}

// Store seals logins into Dir on the card. Fields are set once before use.
type Store struct {
	Card, Dir, Mounts string // /mnt/mmc, /mnt/mmc/.q2vault, /proc/mounts
	Master            [32]byte
	Rand              io.Reader
	Now               func() time.Time

	mu    sync.RWMutex // EraseAll takes it whole; every other call shares it
	locks sync.Map     // id -> *sync.Mutex
}

func (s *Store) idLock(id string) *sync.Mutex {
	m, _ := s.locks.LoadOrStore(id, new(sync.Mutex))
	return m.(*sync.Mutex)
}

// mounted reports whether a line of Mounts has Card as its second field.
func (s *Store) mounted() error {
	f, err := os.Open(s.Mounts)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) >= 2 && fs[1] == s.Card {
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return ErrCardAway
}

func (s *Store) path(id string) string { return filepath.Join(s.Dir, id+".sealed") }

// Get opens an app's secret. A file that does not open is set aside as .bad
// and reported as ErrNone.
func (s *Store) Get(id string) ([]byte, error) {
	if !idRe.MatchString(id) {
		return nil, ErrBadID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	l := s.idLock(id)
	l.Lock()
	defer l.Unlock()
	if err := s.mounted(); err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNone
	}
	if err != nil {
		return nil, err
	}
	key := seal.AppKey(s.Master, id)
	secret, err := seal.Open(key, id, blob)
	if err != nil {
		if errors.Is(err, seal.ErrBad) {
			if rerr := os.Rename(s.path(id), s.path(id)+".bad"); rerr != nil {
				return nil, rerr
			}
			return nil, ErrNone
		}
		return nil, err
	}
	return secret, nil
}

// Put seals and writes an app's secret.
func (s *Store) Put(id string, secret []byte) error {
	if !idRe.MatchString(id) {
		return ErrBadID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	l := s.idLock(id)
	l.Lock()
	defer l.Unlock()
	if err := s.mounted(); err != nil {
		return err
	}
	key := seal.AppKey(s.Master, id)
	blob, err := seal.Seal(key, id, secret, s.Rand)
	if err != nil {
		return err
	}
	if err := os.Mkdir(s.Dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return writeAtomic(s.path(id), blob, 0o600)
}

// Delete removes an app's sealed file; nothing there is fine.
func (s *Store) Delete(id string) error {
	if !idRe.MatchString(id) {
		return ErrBadID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	l := s.idLock(id)
	l.Lock()
	defer l.Unlock()
	if err := s.mounted(); err != nil {
		return err
	}
	err := os.Remove(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(s.Dir)
}

// List returns the saved logins, by id order.
func (s *Store) List() ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.mounted(); err != nil {
		return nil, err
	}
	des, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, de := range des {
		id, ok := strings.CutSuffix(de.Name(), ".sealed")
		if !ok || !idRe.MatchString(id) || !de.Type().IsRegular() {
			continue
		}
		fi, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, Entry{ID: id, Saved: fi.ModTime()})
	}
	return out, nil
}

// EraseAll removes every sealed file (and .bad, .tmp) and adopts newMaster.
func (s *Store) EraseAll(newMaster [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mounted(); err != nil {
		return err
	}
	des, err := os.ReadDir(s.Dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var errs []error
	for _, de := range des {
		n := de.Name()
		if strings.HasSuffix(n, ".sealed") || strings.HasSuffix(n, ".sealed.bad") || strings.HasSuffix(n, ".sealed.tmp") {
			if err := os.Remove(filepath.Join(s.Dir, n)); err != nil {
				errs = append(errs, fmt.Errorf("store: erase %s: %w", n, err))
			}
		}
	}
	s.Master = newMaster // adopted even if some file stayed: old files can't open under it
	return errors.Join(errs...)
}

// Clean removes leftover *.sealed.tmp files from cut-off writes.
func (s *Store) Clean() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mounted(); err != nil {
		return err
	}
	tmps, err := filepath.Glob(filepath.Join(s.Dir, "*.sealed.tmp"))
	if err != nil {
		return err
	}
	for _, p := range tmps {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
