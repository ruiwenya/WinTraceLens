package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEvidencePlanIncludesDependenciesOnce(t *testing.T) {
	plan, err := evidenceCollectionPlan([]string{"behavior", "findings", "investigation", "yara", "process-modules"})
	if err != nil {
		t.Fatal(err)
	}
	indexes := map[string]int{}
	for i, id := range plan {
		if id == "yara" {
			t.Fatal("YARA must not run without user rules")
		}
		if _, exists := indexes[id]; exists {
			t.Fatalf("duplicate step %s", id)
		}
		indexes[id] = i
		for _, dependency := range evidenceDependencies[id] {
			index, ok := indexes[dependency]
			if !ok || index >= i {
				t.Fatalf("%s before dependency %s", id, dependency)
			}
		}
	}
	if plan, err := evidenceCollectionPlan([]string{"connections"}); err != nil || !reflect.DeepEqual(plan, []string{"connections"}) {
		t.Fatalf("unrelated collectors: %v %v", plan, err)
	}
	for _, sources := range [][]string{{}, {"yara"}, {"ai-session"}, {"native-files"}} {
		if _, err := evidenceCollectionPlan(sources); err == nil {
			t.Fatalf("unsafe/empty plan accepted %v", sources)
		}
	}
}

func TestEvidenceCollectionRequestBounds(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.Local)
	req := evidenceCollectRequest{Sources: []string{"connections"}}
	if err := req.validate(now); err != nil {
		t.Fatal(err)
	}
	if req.Start != "2026-08-27" || req.End != "2026-09-02" || req.MaxRecords != 500 || req.MaxProcesses != 300 {
		t.Fatalf("defaults: %+v", req)
	}
	for _, bad := range []evidenceCollectRequest{
		{Sources: []string{}}, {MaxRecords: -1}, {MaxProcesses: 801},
		{Start: "invalid"}, {Start: "2026-09-04", End: "2026-09-02"},
		{Start: "2026-01-01", End: "2026-09-02"},
	} {
		if err := bad.validate(now); err == nil {
			t.Fatalf("invalid request accepted: %+v", bad)
		}
	}
}

func TestEvidenceStageProgressPartialAndCancellation(t *testing.T) {
	var events []evidenceProgress
	steps := []evidenceStep{
		{ID: "one", Run: func(ctx context.Context, progress func(int, int, string)) ([]string, error) {
			progress(1, 2, "half")
			progress(2, 2, "done")
			return nil, nil
		}},
		{ID: "two", Run: func(context.Context, func(int, int, string)) ([]string, error) { return nil, errors.New("unavailable") }},
	}
	if err := runEvidenceSteps(context.Background(), steps, func(event evidenceProgress) error { events = append(events, event); return nil }); err != nil {
		t.Fatal(err)
	}
	last := -1
	for _, event := range events {
		if event.Percent < last || event.Percent > 100 {
			t.Fatalf("invalid progress %+v", event)
		}
		last = event.Percent
	}
	if final := events[len(events)-1]; final.Type != "done" || final.Status != "partial" || final.Percent != 100 {
		t.Fatalf("failed collection reported as success: %+v", final)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ranSecond := false
	steps[0].Run = func(context.Context, func(int, int, string)) ([]string, error) { cancel(); return nil, nil }
	steps[1].Run = func(context.Context, func(int, int, string)) ([]string, error) { ranSecond = true; return nil, nil }
	if err := runEvidenceSteps(ctx, steps, func(evidenceProgress) error { return nil }); !errors.Is(err, context.Canceled) || ranSecond {
		t.Fatal("cancel continued collection", err)
	}
	if err := runEvidenceSteps(context.Background(), steps, func(evidenceProgress) error { return errors.New("disconnected") }); err == nil {
		t.Fatal("disconnected stream continued")
	}
}

func TestEvidenceCollectRejectsInvalidAndConcurrentRequests(t *testing.T) {
	s := New(Options{})
	call := func(method, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleEvidenceCollect(w, httptest.NewRequest(method, "/api/export/evidence/collect", strings.NewReader(body)))
		return w
	}
	if w := call(http.MethodGet, ""); w.Code != 405 {
		t.Fatal(w.Code)
	}
	for _, body := range []string{`{broken`, `{"sources":[]}`, `{"sources":["yara"]}`, `{"sources":["connections"],"maxRecords":999999}`} {
		if w := call(http.MethodPost, body); w.Code != 400 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
	s.evidenceCollectMu.Lock()
	w := call(http.MethodPost, `{"sources":["connections"]}`)
	s.evidenceCollectMu.Unlock()
	if w.Code != 409 {
		t.Fatal("concurrent collection allowed", w.Code)
	}
	unauthorized := httptest.NewRecorder()
	s.Routes().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/export/evidence/collect", strings.NewReader(`{"sources":["connections"]}`)))
	if unauthorized.Code != 403 {
		t.Fatal("unauthorized collection allowed")
	}
}
