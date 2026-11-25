// Package missing tracks apps whose login is stored but whose app is gone,
// and says when a login has been orphaned long enough to delete.
//
// Deletion is deliberately slow: App Store updates move files briefly, a
// swapped card makes every app look missing, and a same-day reinstall should
// keep its login.
package missing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Grace is how long an app must stay missing before its login goes.
const Grace = 7 * 24 * time.Hour

// State maps an app id to when it was first seen missing.
type State struct {
	Missing map[string]time.Time `json:"missing"`
}

// Load reads the state file. A missing file is an empty state. A corrupt or
// unreadable file returns an empty, usable State together with the error; the
// caller decides, and treating it as empty is safe (the clocks just restart,
// so logins are kept longer, never deleted sooner).
func Load(path string) (State, error) {
	empty := State{Missing: map[string]time.Time{}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return empty, err
	}
	if s.Missing == nil {
		s.Missing = map[string]time.Time{}
	}
	return s, nil
}

// Save writes the whole state to path, mode 0600, via tmp + fsync + rename.
func (s State) Save(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	err = f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Sweep updates s for the stored login ids and returns the ids whose login
// should now be deleted. An id not installed is stamped with now the first
// time; once missing for Grace or longer it is returned and dropped. An
// installed id is dropped from Missing, as is any id no longer in ids.
func Sweep(s *State, ids []string, installed func(id string) bool, now time.Time) (remove []string) {
	next := make(map[string]time.Time, len(ids))
	for _, id := range ids {
		if installed(id) {
			continue
		}
		first, ok := s.Missing[id]
		if !ok {
			first = now
		}
		if now.Sub(first) >= Grace {
			remove = append(remove, id)
			continue
		}
		next[id] = first
	}
	s.Missing = next
	return remove
}
