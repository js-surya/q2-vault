// Package pages draws the Vault's page on the Q2 (Q2SPOT/1): the apps with a saved login, Remove,
// Erase All Logins and About. It only ever sees ids, names and dates; never a secret.
package pages

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"q2-vault/internal/q2spot"
	"q2-vault/internal/store"
)

// Deps are the page's ties to the app.
type Deps struct {
	List     func() ([]store.Entry, error)
	Names    func() map[string]string    // id -> name from the app's q2app
	Missing  func() map[string]time.Time // id -> first seen missing
	Remove   func(id string) error
	EraseAll func() error
	Now      func() time.Time
	Version  string
	OnPage   func() // called for every request: keeps the Vault running while the page is open
}

const confirmWindow = 5 * time.Second

func ok(rows ...q2spot.Row) q2spot.Reply { return q2spot.Reply{Status: "ok", Rows: rows} }
func say(msg string) q2spot.Reply        { return q2spot.Reply{Status: "ok", Message: msg} }
func fail(format string, a ...any) q2spot.Reply {
	return q2spot.Reply{Status: "error", Message: fmt.Sprintf(format, a...)}
}

// Handler answers the page's requests.
func Handler(d Deps) q2spot.Handler {
	var mu sync.Mutex
	var armed string // "remove <id>" or "erase", empty when nothing is waiting for a second press
	var armedAt time.Time
	if d.Now == nil {
		d.Now = time.Now
	}
	name := func(id string) string {
		if d.Names != nil {
			if n := d.Names()[id]; n != "" {
				return n
			}
		}
		return id
	}
	// confirm is true on the second press of what, within the window.
	confirm := func(what string) bool {
		mu.Lock()
		defer mu.Unlock()
		now := d.Now()
		if armed == what && now.Sub(armedAt) <= confirmWindow {
			armed = ""
			return true
		}
		armed, armedAt = what, now
		return false
	}
	return func(op string, args []string) q2spot.Reply {
		if d.OnPage != nil {
			d.OnPage()
		}
		arg := ""
		if len(args) > 0 {
			arg = args[0]
		}
		if op != "remove" && op != "eraseall" {
			mu.Lock()
			armed = ""
			mu.Unlock()
		}
		switch op {
		case "menu":
			entries, err := d.List()
			if err != nil {
				return fail("Couldn't read the saved logins")
			}
			missing := map[string]time.Time{}
			if d.Missing != nil {
				missing = d.Missing()
			}
			type item struct {
				id, title string
				saved     time.Time
			}
			items := make([]item, len(entries))
			for i, e := range entries {
				items[i] = item{e.ID, name(e.ID), e.Saved}
			}
			// newest first as the spec shows, an app that isn't installed last
			slices.SortFunc(items, func(a, b item) int {
				_, am := missing[a.id]
				_, bm := missing[b.id]
				if am != bm {
					if am {
						return 1
					}
					return -1
				}
				if c := b.saved.Compare(a.saved); c != 0 {
					return c
				}
				return strings.Compare(a.id, b.id)
			})
			noun := "saved logins"
			if len(items) == 1 {
				noun = "saved login"
			}
			rows := []q2spot.Row{{Kind: "info", Title: fmt.Sprintf("Running · %d %s", len(items), noun)}}
			for _, it := range items {
				sub := "saved " + it.saved.Format("2 Jan")
				if _, gone := missing[it.id]; gone {
					sub = "(not installed)"
				}
				rows = append(rows, q2spot.Row{Kind: "list", URI: "app", Title: it.title, Subtitle: sub, Context: it.id})
			}
			rows = append(rows,
				q2spot.Row{Kind: "action", URI: "eraseall", Title: "Erase All Logins"},
				q2spot.Row{Kind: "list", URI: "about", Title: "About"})
			return ok(rows...)
		case "app":
			entries, err := d.List()
			if err != nil {
				return fail("Couldn't read the saved logins")
			}
			for _, e := range entries {
				if e.ID == arg {
					return ok(
						q2spot.Row{Kind: "info", Title: name(arg), Subtitle: "saved " + e.Saved.Format("2 Jan")},
						q2spot.Row{Kind: "action", URI: "remove", Title: "Remove", Subtitle: "It asks to sign in next time", Context: arg})
				}
			}
			return fail("No saved login")
		case "remove":
			if arg == "" {
				return fail("No such app")
			}
			if !confirm("remove " + arg) {
				return say("Press again to remove")
			}
			if err := d.Remove(arg); err != nil {
				return fail("Couldn't remove: %v", err)
			}
			return say("Removed " + name(arg))
		case "eraseall":
			if !confirm("erase") {
				return say("Press again to erase all logins")
			}
			if err := d.EraseAll(); err != nil {
				return fail("Couldn't erase: %v", err)
			}
			return say("All logins erased")
		case "about":
			row := func(title, sub string) q2spot.Row { return q2spot.Row{Kind: "info", Title: title, Subtitle: sub} }
			return ok(
				row("Version", d.Version),
				row("Made by", "Syntax-Error"),
				row("Thanks", "DiamondBond & the Q2 Pod community"),
				row("What it does", "Keeps other apps' logins sealed on the card"))
		}
		return q2spot.Reply{Status: "unsupported"}
	}
}
