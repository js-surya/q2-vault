package pages

import (
	"strings"
	"testing"
	"time"

	"q2-vault/internal/q2spot"
	"q2-vault/internal/store"
)

type rig struct {
	now     time.Time
	removed []string
	erased  int
	pages   int
	h       q2spot.Handler
}

func newRig() *rig {
	r := &rig{now: time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)}
	r.h = Handler(Deps{
		List: func() ([]store.Entry, error) {
			return []store.Entry{
				{ID: "plex", Saved: time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)},
				{ID: "deezer", Saved: time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)},
			}, nil
		},
		Names:    func() map[string]string { return map[string]string{"plex": "Plex"} },
		Missing:  func() map[string]time.Time { return map[string]time.Time{"deezer": r.now} },
		Remove:   func(id string) error { r.removed = append(r.removed, id); return nil },
		EraseAll: func() error { r.erased++; return nil },
		Now:      func() time.Time { return r.now },
		Version:  "1.0",
		OnPage:   func() { r.pages++ },
	})
	return r
}

func TestMenu(t *testing.T) {
	rep := newRig().h("menu", nil)
	if rep.Status != "ok" || len(rep.Rows) != 5 {
		t.Fatalf("%+v", rep)
	}
	if g := rep.Rows[0]; g.Kind != "info" || g.Title != "Running · 2 saved logins" {
		t.Errorf("%+v", g)
	}
	if g := rep.Rows[1]; g.Kind != "list" || g.Title != "Plex" || g.Subtitle != "saved 25 Nov" || g.Context != "plex" {
		t.Errorf("%+v", g)
	}
	if g := rep.Rows[2]; g.Kind != "list" || g.Title != "deezer" || g.Subtitle != "(not installed)" {
		t.Errorf("%+v", g)
	}
	if rep.Rows[3].Title != "Erase All Logins" || rep.Rows[4].Title != "About" {
		t.Errorf("%+v", rep.Rows[3:])
	}
}

func TestRemoveAsksFirst(t *testing.T) {
	r := newRig()
	page := r.h("app", []string{"plex"})
	var rm *q2spot.Row
	for i := range page.Rows {
		if page.Rows[i].Title == "Remove" {
			rm = &page.Rows[i]
		}
	}
	if rm == nil {
		t.Fatalf("no Remove: %+v", page)
	}
	if rep := r.h(rm.URI, []string{rm.Context}); rep.Message != "Press again to remove" || len(r.removed) != 0 {
		t.Fatalf("%+v %v", rep, r.removed)
	}
	r.now = r.now.Add(4 * time.Second)
	r.h(rm.URI, []string{rm.Context})
	if len(r.removed) != 1 || r.removed[0] != "plex" {
		t.Fatalf("%v", r.removed)
	}
	// too late: asks again
	r.h(rm.URI, []string{"plex"})
	r.now = r.now.Add(6 * time.Second)
	r.h(rm.URI, []string{"plex"})
	if len(r.removed) != 1 {
		t.Fatalf("%v", r.removed)
	}
	// another op disarms
	r.h(rm.URI, []string{"plex"}) // armed
	r.h("about", nil)
	if rep := r.h(rm.URI, []string{"plex"}); rep.Message != "Press again to remove" || len(r.removed) != 1 {
		t.Fatalf("%+v", rep)
	}
}

func TestEraseAllTwoPresses(t *testing.T) {
	r := newRig()
	if rep := r.h("eraseall", nil); rep.Message != "Press again to erase all logins" || r.erased != 0 {
		t.Fatalf("%+v", rep)
	}
	r.now = r.now.Add(2 * time.Second)
	r.h("eraseall", nil)
	if r.erased != 1 {
		t.Fatal(r.erased)
	}
	r.h("eraseall", nil)
	r.h("menu", nil)
	r.h("eraseall", nil)
	if r.erased != 1 {
		t.Fatal("disarm failed")
	}
}

func TestOnPage(t *testing.T) {
	r := newRig()
	for _, op := range []string{"menu", "about", "app", "nonsense"} {
		r.h(op, []string{"plex"})
	}
	if r.pages != 4 {
		t.Fatal(r.pages)
	}
}

func TestNoSecretsAndAbout(t *testing.T) {
	r := newRig()
	for _, rep := range []q2spot.Reply{r.h("menu", nil), r.h("about", nil), r.h("app", []string{"plex"})} {
		for _, row := range rep.Rows {
			if strings.Contains(strings.ToLower(row.Title+row.Subtitle), "password") {
				t.Errorf("%+v", row)
			}
		}
	}
}
