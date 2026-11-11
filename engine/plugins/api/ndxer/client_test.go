// SPDX-License-Identifier: Apache-2.0

package ndxer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "ndx_secret_key_123"

// sleepRecorder replaces real sleeps so tests are instant.
type sleepRecorder struct {
	mu     sync.Mutex
	sleeps []time.Duration
}

func (s *sleepRecorder) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sleeps = append(s.sleeps, d)
	return nil
}

func (s *sleepRecorder) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.sleeps...)
}

func newTestClient(srv *httptest.Server, rec *sleepRecorder) *client {
	b := defaultBackoff()
	b.sleep = rec.sleep
	b.jitter = func() float64 { return 0 }
	return &client{baseURL: srv.URL, key: testKey, http: srv.Client(), retry: b}
}

func page(next string, extraMeta string, names ...string) string {
	n := "null"
	if next != "" {
		n = fmt.Sprintf("%q", next)
	}
	rows := make([]string, len(names))
	for i, name := range names {
		rows[i] = fmt.Sprintf(`{"name":%q}`, name)
	}
	return fmt.Sprintf(`{"meta":{"next_cursor":%s,"units_charged":1%s},"matches":[%s]}`, n, extraMeta, strings.Join(rows, ","))
}

func TestHostnamesPagesToTheEnd(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != hostnamesPath {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "amass" {
			t.Errorf("User-Agent = %q", got)
		}
		q := r.URL.Query()
		if q.Get("q") != "douban.com" || q.Get("limit") != "1000" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		switch q.Get("cursor") {
		case "":
			_, _ = io.WriteString(w, page("c2", "", "a.douban.com", "b.douban.com"))
		case "c2":
			_, _ = io.WriteString(w, page("c3", "", "c.douban.com"))
		case "c3":
			_, _ = io.WriteString(w, page("", "", "d.douban.com"))
		default:
			t.Errorf("unexpected cursor %q", q.Get("cursor"))
		}
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.douban.com", "b.douban.com", "c.douban.com", "d.douban.com"}
	if strings.Join(res.Names, " ") != strings.Join(want, " ") {
		t.Errorf("names = %v", res.Names)
	}
	if res.Pages != 3 || res.Units != 3 || requests.Load() != 3 {
		t.Errorf("pages=%d units=%d requests=%d", res.Pages, res.Units, requests.Load())
	}
}

func TestHostnamesNormaliseAndDedupe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			_, _ = io.WriteString(w, page("c2", "", "WWW.Douban.com.", " mail.douban.com ", "*.api.douban.com", "www.douban.com", "*", "other.example"))
			return
		}
		_, _ = io.WriteString(w, page("", "", "api.douban.com", "MAIL.douban.com"))
	}))
	defer srv.Close()

	keep := func(n string) bool { return strings.HasSuffix(n, ".douban.com") }
	res, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", keep)
	if err != nil {
		t.Fatal(err)
	}
	want := "www.douban.com mail.douban.com api.douban.com"
	if got := strings.Join(res.Names, " "); got != want {
		t.Errorf("names = %q, want %q", got, want)
	}
}

func TestNormaliseName(t *testing.T) {
	cases := map[string]string{
		"Foo.Example.COM.": "foo.example.com",
		"*.a.example.com":  "a.example.com",
		"*.*.example.com":  "example.com",
		"  ":               "",
		"*":                "",
		"*.":               "",
	}
	for in, want := range cases {
		if got := normaliseName(in); got != want {
			t.Errorf("normaliseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostnamesNotFoundIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"no data","request_id":"r1"}}`)
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
	if err != nil || len(res.Names) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestHostnamesPendingThenOK(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = io.WriteString(w, page("", "", "www.douban.com"))
	}))
	defer srv.Close()

	rec := &sleepRecorder{}
	res, err := newTestClient(srv, rec).hostnames(context.Background(), "douban.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Names) != 1 || n.Load() != 3 {
		t.Errorf("names=%v requests=%d", res.Names, n.Load())
	}
	if got := rec.all(); len(got) != 2 || got[0] != 3*time.Second || got[1] != 3*time.Second {
		t.Errorf("sleeps = %v", got)
	}
}

func TestHostnamesPendingGivesUpAfterBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	rec := &sleepRecorder{}
	_, err := newTestClient(srv, rec).hostnames(context.Background(), "douban.com", nil)
	if err == nil || !strings.Contains(err.Error(), "still looking up douban.com") {
		t.Fatalf("err = %v", err)
	}
	var total time.Duration
	for _, d := range rec.all() {
		total += d
	}
	if total != pendingWait {
		t.Errorf("waited %v, want %v", total, pendingWait)
	}
}

func TestHostnames429HonoursRetryAfter(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"code":"rate_limited","message":"slow down","request_id":"r1"}}`)
			return
		}
		_, _ = io.WriteString(w, page("", "", "www.douban.com"))
	}))
	defer srv.Close()

	rec := &sleepRecorder{}
	res, err := newTestClient(srv, rec).hostnames(context.Background(), "douban.com", nil)
	if err != nil || len(res.Names) != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := rec.all(); len(got) != 1 || got[0] != 7*time.Second {
		t.Errorf("sleeps = %v", got)
	}
}

func TestHostnames5xxRetriesThenGivesUp(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	rec := &sleepRecorder{}
	_, err := newTestClient(srv, rec).hostnames(context.Background(), "douban.com", nil)
	if err == nil || !strings.Contains(err.Error(), "gave up after 5 attempts") || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("err = %v", err)
	}
	if n.Load() != 5 {
		t.Errorf("requests = %d", n.Load())
	}
	// exponential steps with zero jitter: half of 1s, 2s, 4s, 8s
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}
	if got := rec.all(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
}

func TestHostnames5xxThenOK(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, page("", "", "www.douban.com"))
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
	if err != nil || len(res.Names) != 1 || n.Load() != 3 {
		t.Fatalf("res=%+v err=%v requests=%d", res, err, n.Load())
	}
}

func TestHostnamesNonRetryable4xxSurfacesCode(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"code":"invalid_query","message":"q is not a domain","request_id":"req-42"}}`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"invalid_query", "q is not a domain", "req-42", "HTTP 400"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q lacks %q", err, want)
		}
	}
	if n.Load() != 1 {
		t.Errorf("requests = %d, want 1 (no retry)", n.Load())
	}
	if isFatal(err) {
		t.Error("400 must not be fatal")
	}
}

func TestHostnamesFatalStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":{"code":"denied","message":"no","request_id":"r"}}`)
		}))
		_, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
		srv.Close()
		if !isFatal(err) {
			t.Errorf("status %d: err %v is not fatal", status, err)
		}
	}
}

func TestHostnamesFailFastKeepsFirstPage(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = io.WriteString(w, page("c2", `,"units_to_complete":40,"units_remaining":12`, "www.douban.com", "mail.douban.com"))
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.FailFast || res.UnitsToComplete != 40 || res.UnitsRemaining != 12 || len(res.Names) != 2 || n.Load() != 1 {
		t.Errorf("res=%+v requests=%d", res, n.Load())
	}
}

func TestHostnamesKeepsNamesBeforeAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			_, _ = io.WriteString(w, page("c2", "", "www.douban.com"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
	if err == nil || len(res.Names) != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("dial failed for " + r.Header.Get("Authorization"))
}

func TestKeyNeverInErrors(t *testing.T) {
	// a transport error that would carry the key
	c := &client{baseURL: "http://ndxer.invalid", key: testKey, http: &http.Client{Transport: failingTransport{}}, retry: backoff{maxAttempts: 2, sleep: (&sleepRecorder{}).sleep}}
	_, err := c.hostnames(context.Background(), "douban.com", nil)
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("transport err = %v", err)
	}
	_, err = c.related(context.Background(), "douban.com")
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("related transport err = %v", err)
	}

	// an API error body echoing the key
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"invalid_key","message":"key `+testKey+` is not valid","request_id":"r"}}`)
	}))
	defer srv.Close()
	_, err = newTestClient(srv, &sleepRecorder{}).hostnames(context.Background(), "douban.com", nil)
	if err == nil || strings.Contains(err.Error(), testKey) || !strings.Contains(err.Error(), "invalid_key") {
		t.Errorf("api err = %v", err)
	}
}

func TestDelayCapsAndRetryAfterDate(t *testing.T) {
	b := backoff{base: time.Second, maxWait: 10 * time.Second, jitter: func() float64 { return 0.999 }}
	if d := b.delay(10, ""); d > 10*time.Second {
		t.Errorf("delay not capped: %v", d)
	}
	if d := b.delay(1, "120"); d != 10*time.Second {
		t.Errorf("Retry-After not capped: %v", d)
	}
	future := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	if d := b.delay(1, future); d <= 0 || d > 5*time.Second {
		t.Errorf("Retry-After date delay = %v", d)
	}
}

func TestContextCancelStopsSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}
