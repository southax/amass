// SPDX-License-Identifier: Apache-2.0

package ndxer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

const relatedPage1 = `{"meta":{"next_cursor":"c2","units_charged":3,"units_to_complete":1,"units_remaining":50},
"seed":{"signals":[{"class":"infrastructure"},{"class":"subject"},{"class":"infrastructure"}]},
"matches":[
 {"apex":"Owned.example.","class":"subject",
  "evidence":[{"kind":"name_label","key":"owned","n_apexes":9,"provider_name":null},{"kind":"mx_host","key":"mx.shared-owner.example","n_apexes":3,"provider_name":null}],
  "reasons":[{"code":"unique_value","text":"Shares the mail host mx.shared-owner.example."},{"code":"same_name","text":"Same first label."}]},
 {"apex":"maybe.example","class":"review","evidence":[{"kind":"name_label","key":"maybe","n_apexes":4}],"reasons":[{"code":"same_name_only","text":"Only the first label matches."}]},
 {"apex":"seed.example","class":"subject"}]}`

const relatedPage2 = `{"meta":{"next_cursor":null,"units_charged":1},"matches":[{"apex":"second.example","class":"subject"},{"apex":"owned.example","class":"subject"},{"apex":"maybe2.example","class":"review"}]}`

func relatedServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.URL.Path != relatedPath || r.URL.Query().Get("q") != "seed.example" {
			t.Errorf("request = %s", r.URL)
		}
		if r.URL.Query().Get("cursor") == "c2" {
			_, _ = io.WriteString(w, relatedPage2)
			return
		}
		_, _ = io.WriteString(w, relatedPage1)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestRelatedLookupPagesAndClassifies(t *testing.T) {
	srv, n := relatedServer(t)
	res, err := newTestClient(srv, &sleepRecorder{}).related(context.Background(), "seed.example")
	if err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 || res.Pages != 2 || res.Units != 4 || res.InfrastructureSignals != 2 {
		t.Errorf("requests=%d res=%+v", n.Load(), res)
	}
	var got []string
	for _, m := range res.Matches {
		got = append(got, m.Domain+"/"+m.Class)
	}
	want := "owned.example/subject maybe.example/review seed.example/subject second.example/subject maybe2.example/review"
	if strings.Join(got, " ") != want {
		t.Errorf("matches = %v", got)
	}
	owned := res.Matches[0]
	if owned.Why != "Shares the mail host mx.shared-owner.example." || len(owned.Evidence) != 2 {
		t.Errorf("owned = %+v", owned)
	}
}

func TestRelatedFailFastKeepsPages(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = io.WriteString(w, `{"meta":{"next_cursor":"c2","units_charged":2,"units_to_complete":5,"units_remaining":1},"matches":[{"apex":"owned.example","class":"subject"}]}`)
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).related(context.Background(), "seed.example")
	if err != nil || n.Load() != 1 || len(res.Matches) != 1 || !strings.Contains(res.Stopped, "5 more units") {
		t.Fatalf("requests=%d res=%+v err=%v", n.Load(), res, err)
	}
}

func TestRelatedQuotaMidPagingKeepsPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			_, _ = io.WriteString(w, `{"meta":{"next_cursor":"c2","units_charged":1},"matches":[{"apex":"owned.example","class":"subject"}]}`)
			return
		}
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, `{"error":{"code":"quota_exceeded","message":"out of units","request_id":"r"}}`)
	}))
	defer srv.Close()

	res, err := newTestClient(srv, &sleepRecorder{}).related(context.Background(), "seed.example")
	if err != nil || len(res.Matches) != 1 || res.Stopped == "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestParseRelatedConfig(t *testing.T) {
	cases := []struct {
		no, classes string
		enabled     bool
		want        []string
		noteHas     string
	}{
		{"", "", true, []string{"subject"}, ""},
		{"", "review,subject", true, []string{"review", "subject"}, ""},
		{"", "subject, Review ,subject", true, []string{"subject", "review"}, ""},
		{"", "infrastructure", true, []string{"subject"}, "infrastructure is never added"},
		{"", "subject,infrastructure,review", true, []string{"subject", "review"}, "infrastructure is never added"},
		{"", "bogus", true, []string{"subject"}, `unknown class "bogus"`},
		{"1", "review", false, nil, "related scope is OFF"},
		{"0", "", true, []string{"subject"}, ""},
	}
	for _, tc := range cases {
		cfg := parseRelatedConfig(tc.no, tc.classes)
		if cfg.enabled != tc.enabled || !slices.Equal(cfg.classes, tc.want) {
			t.Errorf("(%q,%q) = %+v", tc.no, tc.classes, cfg)
		}
		notes := strings.Join(cfg.notes, "\n")
		if tc.noteHas == "" && notes != "" || tc.noteHas != "" && !strings.Contains(notes, tc.noteHas) {
			t.Errorf("(%q,%q) notes = %q", tc.no, tc.classes, notes)
		}
	}
}

type fakeScope struct {
	mu       sync.Mutex
	inScope  map[string]bool
	enqueued []string
}

func newFakeScope(domains ...string) *fakeScope {
	f := &fakeScope{inScope: map[string]bool{}}
	for _, d := range domains {
		f.inScope[d] = true
	}
	return f
}

func (f *fakeScope) add(d string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inScope[d] {
		return false, nil
	}
	f.inScope[d] = true
	f.enqueued = append(f.enqueued, d)
	return true, nil
}

func bufLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func lookupFixture(t *testing.T) *relatedResult {
	t.Helper()
	srv, _ := relatedServer(t)
	res, err := newTestClient(srv, &sleepRecorder{}).related(context.Background(), "seed.example")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestExpandAddsSubjectCountsReview(t *testing.T) {
	res := lookupFixture(t)
	log, buf := bufLogger()
	st := newTracker().get("s1", nil)
	scope := newFakeScope("seed.example")

	added := expandRelated(log, st, "seed.example", res, parseRelatedConfig("", ""), false, scope.add)
	if strings.Join(added, " ") != "owned.example second.example" || strings.Join(scope.enqueued, " ") != "owned.example second.example" {
		t.Errorf("added=%v enqueued=%v", added, scope.enqueued)
	}
	out := buf.String()
	for _, want := range []string{
		"added 2 domains ndxer links to the same owner",
		"domains=\"owned.example second.example\"",
		"class=subject",
		"Shares the mail host mx.shared-owner.example.",
		"mx_host mx.shared-owner.example",
		"name_label owned",
		"NOT added: 2 review domains",
		"NDXER_RELATED_CLASSES=subject,review",
		"maybe.example maybe2.example",
		"2 shared signals belong to infrastructure providers",
		"4 units charged (2 pages)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if seed, ok := st.wasAdded("owned.example"); !ok || seed != "seed.example" {
		t.Errorf("owned.example not tracked as added")
	}
}

func TestExpandAddsReviewWhenConfigured(t *testing.T) {
	res := lookupFixture(t)
	log, buf := bufLogger()
	st := newTracker().get("s1", nil)
	scope := newFakeScope("seed.example")

	added := expandRelated(log, st, "seed.example", res, parseRelatedConfig("", "subject,review"), false, scope.add)
	if strings.Join(added, " ") != "owned.example second.example maybe.example maybe2.example" {
		t.Errorf("added = %v", added)
	}
	if strings.Contains(buf.String(), "NOT added") {
		t.Errorf("review must not be reported as not added:\n%s", buf.String())
	}
}

func TestExpandRigidListsWithoutAdding(t *testing.T) {
	res := lookupFixture(t)
	log, buf := bufLogger()
	st := newTracker().get("s1", nil)
	scope := newFakeScope("seed.example")

	added := expandRelated(log, st, "seed.example", res, parseRelatedConfig("", ""), true, scope.add)
	if len(added) != 0 || len(scope.enqueued) != 0 {
		t.Errorf("rigid added %v", added)
	}
	out := buf.String()
	for _, want := range []string{"found 2 domains", "rigid boundaries are on", "owned.example second.example", "Shares the mail host"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}

func TestExpandSkipsAlreadyInScope(t *testing.T) {
	res := lookupFixture(t)
	log, buf := bufLogger()
	st := newTracker().get("s1", nil)
	scope := newFakeScope("seed.example", "owned.example")

	added := expandRelated(log, st, "seed.example", res, parseRelatedConfig("", ""), false, scope.add)
	if strings.Join(added, " ") != "second.example" {
		t.Errorf("added = %v", added)
	}
	if _, ok := st.wasAdded("owned.example"); ok {
		t.Error("a domain already in scope must stay a seed of its own")
	}
	if !strings.Contains(buf.String(), "1 related domains were already in scope") {
		t.Errorf("log:\n%s", buf.String())
	}
}

func TestExpandAddFailureIsLoggedAndReleased(t *testing.T) {
	res := lookupFixture(t)
	log, buf := bufLogger()
	st := newTracker().get("s1", nil)
	add := func(d string) (bool, error) { return false, errors.New("boom") }

	added := expandRelated(log, st, "seed.example", res, parseRelatedConfig("", ""), false, add)
	if len(added) != 0 {
		t.Errorf("added = %v", added)
	}
	if _, ok := st.wasAdded("owned.example"); ok {
		t.Error("failed addition still tracked")
	}
	if !strings.Contains(buf.String(), "could not add owned.example: boom") {
		t.Errorf("log:\n%s", buf.String())
	}
}

func TestOneHopGuard(t *testing.T) {
	res := lookupFixture(t)
	log, _ := bufLogger()
	tr := newTracker()
	st := tr.get("s1", nil)
	cfg := parseRelatedConfig("", "")
	scope := newFakeScope("seed.example")

	if !shouldLookupRelated(cfg, st, "seed.example") {
		t.Fatal("the user's domain must get a related lookup")
	}
	expandRelated(log, st, "seed.example", res, cfg, false, scope.add)

	// the added domain comes back through the handler as an in-scope domain
	if shouldLookupRelated(cfg, tr.get("s1", nil), "owned.example") {
		t.Error("an added domain must not get another related lookup")
	}
	// another session is independent
	if !shouldLookupRelated(cfg, tr.get("s2", nil), "owned.example") {
		t.Error("session state leaked across sessions")
	}
	// a second seed linking to the same domain does not add it twice
	again := expandRelated(log, st, "seed.example", res, cfg, false, scope.add)
	if len(again) != 0 {
		t.Errorf("re-added %v", again)
	}
	if shouldLookupRelated(parseRelatedConfig("1", ""), tr.get("s3", nil), "x.example") {
		t.Error("NDXER_NO_RELATED must turn the lookup off")
	}
}

func TestReserveIsSafeConcurrently(t *testing.T) {
	st := newTracker().get("s1", nil)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st.reserve("owned.example", "seed.example") {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Errorf("wins = %d", wins.Load())
	}
}

func TestTrackerForgetsFinishedSessions(t *testing.T) {
	tr := newTracker()
	done := false
	tr.get("old", func() bool { return done })
	done = true
	tr.get("new", nil)
	if _, ok := tr.sessions["old"]; ok {
		t.Error("finished session kept")
	}
}

func TestFatalTurnsRelatedOffOnceWithoutKey(t *testing.T) {
	p := &ndxerPlugin{related: parseRelatedConfig("", "")}
	log, buf := bufLogger()
	st := newTracker().get("s1", nil)
	c := &client{key: testKey}
	err := &apiError{Status: http.StatusUnauthorized, Code: "invalid_key", Message: c.redactString("key " + testKey + " rejected")}

	if !p.maybeTurnRelatedOff(log, st, err) || !p.maybeTurnRelatedOff(log, st, err) {
		t.Fatal("401 must be fatal")
	}
	if p.maybeTurnRelatedOff(log, st, &apiError{Status: http.StatusBadRequest}) {
		t.Error("400 must not be fatal")
	}
	out := buf.String()
	if strings.Count(out, "off for the rest of this session") != 1 {
		t.Errorf("want one notice:\n%s", out)
	}
	if strings.Contains(out, testKey) {
		t.Error("key leaked into the log")
	}
	if shouldLookupRelated(p.related, st, "seed.example") {
		t.Error("related still on after a fatal status")
	}
}

func TestAPIKeyFromConfigThenEnv(t *testing.T) {
	p := &ndxerPlugin{name: pluginName, envKey: "from-env"}
	if got := p.apiKey(nil); got != "from-env" {
		t.Errorf("key = %q", got)
	}

	cfg := config.NewConfig()
	cfg.DataSrcConfigs = &config.DataSourceConfig{Datasources: []*config.DataSource{{
		Name:  "NDXER",
		Creds: map[string]*config.Credentials{"account": {Apikey: " from-config "}},
	}}}
	if got := p.apiKey(cfg); got != "from-config" {
		t.Errorf("key = %q", got)
	}

	cfg.DataSrcConfigs.Datasources[0].Creds["account"].Apikey = ""
	if got := p.apiKey(cfg); got != "from-env" {
		t.Errorf("key = %q", got)
	}
}
