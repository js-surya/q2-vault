package q2spot

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestEscapeRoundTrip(t *testing.T) {
	in := "a%\tb\nc\r"
	esc := Escape(in)
	if esc != "a%25%09b%0Ac%0D" {
		t.Fatalf("Escape = %q", esc)
	}
	back, err := Unescape(esc)
	if err != nil || back != in {
		t.Fatalf("Unescape = %q, %v", back, err)
	}
	if s, _ := Unescape("café %2541"); s != "café %41" {
		t.Fatalf("UTF-8 and a literal %%: %q", s)
	}
}

func TestUnescapeMalformed(t *testing.T) {
	for _, bad := range []string{"%zz", "%4", "%", "a%g0"} {
		if _, err := Unescape(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// serve starts Serve on a socket in a temp dir; ask sends one raw request and returns the raw reply.
func serve(t *testing.T, h Handler) (ask func(string) string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, sock, h)
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func(req string) string {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(req))
		c.(*net.UnixConn).CloseWrite()
		b, _ := io.ReadAll(c)
		return string(b)
	}
}

func TestServeOneRequest(t *testing.T) {
	var gotOp string
	var gotArgs []string
	ask := serve(t, func(op string, args []string) Reply {
		gotOp, gotArgs = op, args
		return Reply{Status: "ok", Rows: []Row{{Kind: "info", Title: "Connected\tnow"}}}
	})
	out := ask("Q2SPOT/1\n7\tmenu\tx%09y\n")
	want := "Q2SPOT/1\n7\tok\t\t\ninfo\t\tConnected%09now\t\t\t\n"
	if out != want {
		t.Fatalf("reply %q, want %q", out, want)
	}
	if gotOp != "menu" || len(gotArgs) != 1 || gotArgs[0] != "x\ty" {
		t.Fatalf("handler got %q %q", gotOp, gotArgs)
	}
}

func TestOversizedRequestBad(t *testing.T) {
	ask := serve(t, func(string, []string) Reply { return Reply{Status: "ok"} })
	out := ask("Q2SPOT/1\n3\tmenu\t" + strings.Repeat("a", 9<<10) + "\n")
	if !strings.HasPrefix(out, "Q2SPOT/1\n") || strings.Split(strings.Split(out, "\n")[1], "\t")[1] != "bad" {
		t.Fatalf("reply %q", out[:min(len(out), 60)])
	}
}

func TestMalformedRequestBad(t *testing.T) {
	ask := serve(t, func(string, []string) Reply { return Reply{Status: "ok"} })
	for _, req := range []string{"HTTP/1.1\n", "Q2SPOT/1\n", "Q2SPOT/1\nx\tmenu\n", "Q2SPOT/1\n4\tme%zznu\n"} {
		out := ask(req)
		if lines := strings.Split(out, "\n"); len(lines) < 2 || strings.Split(lines[1], "\t")[1] != "bad" {
			t.Errorf("%q: reply %q", req, out)
		}
	}
}

func TestTitleCutOnRuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 200) // 400 bytes of two-byte runes
	ask := serve(t, func(string, []string) Reply {
		return Reply{Status: "ok", Message: strings.Repeat("m", 300), Rows: []Row{{Kind: "info", Title: long, Subtitle: "x" + long}}}
	})
	lines := strings.Split(ask("Q2SPOT/1\n1\tmenu\n"), "\n")
	head := strings.Split(lines[1], "\t")
	row := strings.Split(lines[2], "\t")
	if len(head[2]) > 120 || len(row[2]) > 255 || len(row[3]) > 255 {
		t.Fatalf("lengths message %d title %d subtitle %d", len(head[2]), len(row[2]), len(row[3]))
	}
	if !utf8.ValidString(row[2]) || !utf8.ValidString(row[3]) {
		t.Fatalf("cut inside a character")
	}
}

func TestAtMostFiftyRows(t *testing.T) {
	ask := serve(t, func(string, []string) Reply {
		rows := make([]Row, 70)
		for i := range rows {
			rows[i] = Row{Kind: "info", Title: "r"}
		}
		return Reply{Status: "ok", Rows: rows}
	})
	if n := strings.Count(ask("Q2SPOT/1\n1\tmachines\n"), "\n") - 2; n != 50 {
		t.Fatalf("%d rows", n)
	}
}

func TestStaleSocketReplaced(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close() // a socket file left by a killed run
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, sock, func(string, []string) Reply { return Reply{Status: "ok"} }) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-errc:
		t.Fatalf("Serve: %v", err)
	default:
	}
	if _, err := net.Dial("unix", sock); err != nil {
		t.Fatal(err)
	}
}
