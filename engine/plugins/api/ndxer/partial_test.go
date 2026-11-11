// SPDX-License-Identifier: Apache-2.0

package ndxer

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const partialMeta = `,"status":"partial"`

// partialThen answers a partial first page `partials` times, then the complete one.
func partialThen(partials int32) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= partials {
			w.Header().Set("Retry-After", "5")
			_, _ = io.WriteString(w, page("", partialMeta, "www.douban.com"))
			return
		}
		_, _ = io.WriteString(w, page("", "", "www.douban.com", "api.douban.com"))
	}))
	return srv, &n
}

func TestPartialWaitsForTheCompleteListByDefault(t *testing.T) {
	srv, n := partialThen(2)
	defer srv.Close()

	rec := &sleepRecorder{}
	c := newTestClient(srv, rec)
	var notes int
	c.onWait = func(subject, path string, partial bool) {
		notes++
		if subject != "douban.com" || path != hostnamesPath || !partial {
			t.Errorf("note(%q, %q, %v)", subject, path, partial)
		}
	}
	res, err := c.hostnames(context.Background(), "douban.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Partial || len(res.Names) != 2 || n.Load() != 3 {
		t.Errorf("partial=%v names=%v requests=%d", res.Partial, res.Names, n.Load())
	}
	if got := rec.all(); len(got) != 2 || got[0] != 5*time.Second {
		t.Errorf("sleeps = %v", got)
	}
	if notes != 1 {
		t.Errorf("wait noted %d times, want 1", notes)
	}
}

func TestPartialWithNoWaitKeepsThePageAndFlagsIt(t *testing.T) {
	srv, n := partialThen(5)
	defer srv.Close()

	rec := &sleepRecorder{}
	c := newTestClient(srv, rec)
	c.noWait = true
	res, err := c.hostnames(context.Background(), "douban.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial || res.PartialCapped || len(res.Names) != 1 || n.Load() != 1 {
		t.Errorf("partial=%v capped=%v names=%v requests=%d", res.Partial, res.PartialCapped, res.Names, n.Load())
	}
	if len(rec.all()) != 0 {
		t.Errorf("slept %v with no-wait", rec.all())
	}
}

func TestPartialAfterTheWholeWaitKeepsWhatIsThere(t *testing.T) {
	srv, _ := partialThen(1 << 20)
	defer srv.Close()

	rec := &sleepRecorder{}
	res, err := newTestClient(srv, rec).hostnames(context.Background(), "douban.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial || !res.PartialCapped || len(res.Names) != 1 {
		t.Errorf("partial=%v capped=%v names=%v", res.Partial, res.PartialCapped, res.Names)
	}
	var total time.Duration
	for _, d := range rec.all() {
		total += d
	}
	if total != pendingWait {
		t.Errorf("waited %v, want %v", total, pendingWait)
	}
}

func TestRelatedPartialWaitsToo(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := ""
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "5")
			status = `"status":"partial",`
		}
		_, _ = io.WriteString(w, `{"meta":{`+status+`"next_cursor":null,"units_charged":1},"seed":{"signals":[]},"matches":[{"apex":"douban.net","class":"subject"}]}`)
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).related(context.Background(), "douban.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Partial || len(res.Matches) != 1 || n.Load() != 2 {
		t.Errorf("partial=%v matches=%v requests=%d", res.Partial, res.Matches, n.Load())
	}
}

func TestPendingWithNoWaitSaysSoAndDoesNotWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	rec := &sleepRecorder{}
	c := newTestClient(srv, rec)
	c.noWait = true
	_, err := c.hostnames(context.Background(), "douban.com", nil)
	if err == nil || !strings.Contains(err.Error(), envNoWait) {
		t.Fatalf("err = %v", err)
	}
	if len(rec.all()) != 0 {
		t.Errorf("slept %v with no-wait", rec.all())
	}
}

func TestParseNoWait(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "false": false, "1": true, "true": true, "yes": true} {
		if got := parseNoWait(v); got != want {
			t.Errorf("parseNoWait(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestMessagesNameTheSwitch(t *testing.T) {
	for _, m := range []string{
		waitMessage("douban.com", hostnamesPath, true),
		waitMessage("douban.com", relatedPath, true),
		waitMessage("douban.com", hostnamesPath, false),
		partialMessage("hostnames", "douban.com", 3, false),
	} {
		if !strings.Contains(m, envNoWait) || !strings.Contains(m, "douban.com") {
			t.Errorf("message lacks the domain or the switch: %q", m)
		}
	}
	if m := partialMessage("hostnames", "douban.com", 3, true); !strings.Contains(m, "15 minutes") {
		t.Errorf("capped message: %q", m)
	}
}
