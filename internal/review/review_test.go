package review_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

func quiet(string, ...any) {}

var baseTS = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// scores builds a 7-class probability vector from the values given, padding the
// rest with zero.
func scores(v ...float64) inference.Scores {
	var s inference.Scores
	for i := range v {
		if i < len(s) {
			s[i] = v[i]
		}
	}
	return s
}

// verdict is one stored classification for flow id with the given ensemble class
// and per-model probability vector.
func verdict(id uint64, class string, score float64, sc inference.Scores, opts ...func(*storage.Classification)) storage.Classification {
	c := storage.Classification{
		FlowID:        id,
		TS:            baseTS.Add(time.Duration(id) * time.Second),
		Sensor:        "local",
		Proto:         "TCP",
		InitiatorIP:   "10.0.0.5",
		InitiatorPort: 40000 + uint16(id%1000), //nolint:gosec // small test ids
		ResponderIP:   "10.0.0.9",
		ResponderPort: 80,
		Result: inference.Result{
			FlowID: id, Class: class, Score: score,
			Models: []inference.ModelOutput{
				{ModelID: "heuristic-v1", Role: inference.RolePrimary, Class: class, Score: score, Scores: sc},
			},
		},
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// store returns a memory store holding the given verdicts, oldest first.
func store(cs ...storage.Classification) *storage.Mem {
	st := storage.NewMem(100, 100)
	for _, c := range cs {
		st.PutClassification(c)
	}
	return st
}

// open returns a review store over a fresh temp directory.
func open(t *testing.T, src review.Source) (*review.Store, string) {
	t.Helper()
	dir := t.TempDir()
	return review.Open(dir, src, nil, nil, quiet), dir
}

func mustPut(t *testing.T, s *review.Store, id uint64, st review.State, label, note string) review.Review {
	t.Helper()
	r, err := s.Put(id, st, label, note)
	if err != nil {
		t.Fatalf("Put(%d, %s, %q): %v", id, st, label, err)
	}
	return r
}

// ---- the §16 invariant: the prediction is never overwritten ---------------

// TestPredictionIsNeverOverwritten is the test this package exists for. Once a
// flow has been reviewed, the model's original claim — class, score and model id
// — is frozen. A correction may change the state, the human label, the note and
// updated_at, and it appends to history, but the three predicted_* values must
// come back byte-identical.
func TestPredictionIsNeverOverwritten(t *testing.T) {
	st := store(verdict(7, "normal", 0.62, scores(0.62, 0.30, 0.08)))
	s, _ := open(t, st)

	first := mustPut(t, s, 7, review.StateCorrect, "", "looks like ordinary browsing")
	if first.PredictedClass() != "normal" || first.PredictedScore() != 0.62 || first.ModelID() != "heuristic-v1" {
		t.Fatalf("first review did not capture the prediction: %+v", first)
	}
	if len(first.History) != 0 {
		t.Fatalf("first review should have empty history, got %d entries", len(first.History))
	}
	// The prediction as JSON, so "byte-identical" is literal and not just field
	// equality on floats.
	wantPred := predJSON(t, first)

	// The world moves on: the model is re-run and now says something else. This
	// is exactly the case §16 protects against.
	st.PutClassification(verdict(7, "scan", 0.97, scores(0.01, 0.97, 0.02)))

	time.Sleep(1100 * time.Millisecond) // RFC3339 has one-second resolution
	second, err := s.Put(7, review.StateIncorrect, "brute_force", "it is the mysql hammering")
	if err != nil {
		t.Fatalf("re-review: %v", err)
	}

	if got := predJSON(t, second); got != wantPred {
		t.Errorf("prediction changed on re-review:\n before %s\n after  %s", wantPred, got)
	}
	if second.State != review.StateIncorrect {
		t.Errorf("state = %q, want incorrect", second.State)
	}
	if second.HumanLabel != "brute_force" || second.EffectiveLabel() != "brute_force" {
		t.Errorf("human label = %q / effective %q, want brute_force", second.HumanLabel, second.EffectiveLabel())
	}
	if second.UpdatedAt == first.UpdatedAt {
		t.Errorf("updated_at did not move: %q", second.UpdatedAt)
	}
	if second.CreatedAt != first.CreatedAt {
		t.Errorf("created_at moved: %q → %q", first.CreatedAt, second.CreatedAt)
	}
	if len(second.History) != 1 {
		t.Fatalf("history = %d entries, want 1", len(second.History))
	}
	h := second.History[0]
	if h.State != review.StateCorrect || h.TS != first.UpdatedAt || h.Note != "looks like ordinary browsing" {
		t.Errorf("history[0] = %+v, want the superseded correct decision", h)
	}
	if second.Agrees() {
		t.Errorf("Agrees() = true, but brute_force != normal")
	}

	// And after a reload from disk.
	reloaded := review.Open(s.Dir(), st, nil, nil, quiet)
	got, ok := reloaded.Get(7)
	if !ok {
		t.Fatal("review missing after reload")
	}
	if p := predJSON(t, got); p != wantPred {
		t.Errorf("prediction changed across reload:\n before %s\n after  %s", wantPred, p)
	}
}

// predJSON extracts just the three prediction keys from a Review's JSON form.
func predJSON(t *testing.T, r review.Review) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal review: %v", err)
	}
	out := make([]string, 0, 3)
	for _, k := range []string{"predicted_class", "predicted_score", "model_id"} {
		v, ok := m[k]
		if !ok {
			t.Fatalf("review JSON has no %q key: %s", k, b)
		}
		out = append(out, k+"="+string(v))
	}
	return strings.Join(out, " ")
}

// TestNoExportedWayToSetThePrediction documents lock (2): the write API takes a
// state, a label and a note, and nothing else. If a prediction argument is ever
// added to Put this test's call will stop compiling, which is the point.
func TestNoExportedWayToSetThePrediction(t *testing.T) {
	s, _ := open(t, store(verdict(1, "scan", 0.9, scores(0.1, 0.9))))

	// The compile-time half of the assertion: Put must be assignable to a
	// signature with no prediction parameter. Adding one breaks this line.
	wantSignature := func(func(uint64, review.State, string, string) (review.Review, error)) {}
	wantSignature(s.Put)

	r, err := s.Put(1, review.StateCorrect, "", "")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if r.PredictedClass() != "scan" {
		t.Fatalf("prediction = %q, want scan", r.PredictedClass())
	}
}

// ---- per-state validation -------------------------------------------------

func TestStateValidation(t *testing.T) {
	cases := []struct {
		name    string
		state   review.State
		label   string
		wantErr bool
	}{
		{"correct with no label derives it", review.StateCorrect, "", false},
		{"correct agreeing explicitly", review.StateCorrect, "normal", false},
		{"correct contradicting the prediction", review.StateCorrect, "scan", true},
		{"incorrect with a label", review.StateIncorrect, "scan", false},
		{"incorrect without a label", review.StateIncorrect, "", true},
		{"incorrect agreeing with the prediction", review.StateIncorrect, "normal", true},
		{"unsure with no label", review.StateUnsure, "", false},
		{"unsure with a label", review.StateUnsure, "scan", true},
		{"ignored_pattern with no label", review.StateIgnoredPattern, "", false},
		{"ignored_pattern with a label", review.StateIgnoredPattern, "normal", true},
		{"unreviewed with no label", review.StateUnreviewed, "", false},
		{"unreviewed with a label", review.StateUnreviewed, "normal", true},
		{"not a class", review.StateIncorrect, "definitely_not_a_class", true},
		{"not a state", review.State("maybe"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := open(t, store(verdict(3, "normal", 0.7, scores(0.7, 0.2, 0.1))))
			_, err := s.Put(3, tc.state, tc.label, "")
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("Put(%s, %q) succeeded, want an error", tc.state, tc.label)
			case tc.wantErr && !errors.Is(err, review.ErrInvalid):
				t.Fatalf("Put(%s, %q) → %v, want ErrInvalid", tc.state, tc.label, err)
			case !tc.wantErr && err != nil:
				t.Fatalf("Put(%s, %q): %v", tc.state, tc.label, err)
			}
		})
	}
}

// TestIncorrectRequiresALabelAndEchoesTheValidSet checks the operator-facing
// error text: a rejection has to say what would have worked.
func TestIncorrectRequiresALabelAndEchoesTheValidSet(t *testing.T) {
	s, _ := open(t, store(verdict(4, "normal", 0.7, scores(0.7, 0.3))))
	_, err := s.Put(4, review.StateIncorrect, "", "")
	if err == nil {
		t.Fatal("incorrect with no human_label was accepted")
	}
	for _, want := range []string{"requires human_label", "brute_force", "scan"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestCorrectDerivesTheLabelFromThePrediction(t *testing.T) {
	s, _ := open(t, store(verdict(9, "web_attack", 0.81, scores(0, 0, 0, 0, 0, 0.81, 0.19))))
	r := mustPut(t, s, 9, review.StateCorrect, "", "sqli attempt, confirmed in the logs")
	if r.HumanLabel != "" {
		t.Errorf("human_label = %q, want empty (it is derived)", r.HumanLabel)
	}
	if got := r.EffectiveLabel(); got != "web_attack" {
		t.Errorf("effective label = %q, want web_attack", got)
	}
	if !r.Agrees() {
		t.Error("Agrees() = false for a confirmed prediction")
	}
}

func TestUnknownFlowIsRejected(t *testing.T) {
	s, _ := open(t, store(verdict(1, "normal", 0.9, scores(0.9, 0.1))))
	_, err := s.Put(4242, review.StateUnsure, "", "")
	if !errors.Is(err, review.ErrNoFlow) {
		t.Fatalf("Put on an unknown flow → %v, want ErrNoFlow", err)
	}
	if !strings.Contains(err.Error(), "evicted") {
		t.Errorf("error should explain eviction, got %q", err)
	}
}

func TestNoSourceMeansNoReview(t *testing.T) {
	s := review.Open(t.TempDir(), nil, nil, nil, quiet)
	if _, err := s.Put(1, review.StateCorrect, "", ""); !errors.Is(err, review.ErrNoFlow) {
		t.Fatalf("Put with no source → %v, want ErrNoFlow", err)
	}
}

func TestNoteIsBounded(t *testing.T) {
	s, _ := open(t, store(verdict(1, "normal", 0.9, scores(0.9, 0.1))))
	_, err := s.Put(1, review.StateUnsure, "", strings.Repeat("x", review.MaxNoteLen+1))
	if !errors.Is(err, review.ErrInvalid) {
		t.Fatalf("oversized note → %v, want ErrInvalid", err)
	}
}

// ---- history --------------------------------------------------------------

func TestHistoryAccumulatesEveryCorrection(t *testing.T) {
	s, _ := open(t, store(verdict(2, "normal", 0.55, scores(0.55, 0.45))))

	mustPut(t, s, 2, review.StateUnsure, "", "not sure")
	mustPut(t, s, 2, review.StateIncorrect, "scan", "on reflection: a scan")
	final := mustPut(t, s, 2, review.StateCorrect, "", "no wait, the model was right")

	if len(final.History) != 2 {
		t.Fatalf("history = %d, want 2", len(final.History))
	}
	if final.History[0].State != review.StateUnsure {
		t.Errorf("history[0] = %q, want unsure", final.History[0].State)
	}
	if final.History[1].State != review.StateIncorrect || final.History[1].HumanLabel != "scan" {
		t.Errorf("history[1] = %+v, want the incorrect/scan decision", final.History[1])
	}
	if final.EffectiveLabel() != "normal" {
		t.Errorf("effective label = %q, want the prediction normal", final.EffectiveLabel())
	}
	if final.HumanLabel != "" {
		t.Errorf("human_label = %q, want cleared by the correct decision", final.HumanLabel)
	}
}

// ---- persistence ----------------------------------------------------------

func TestPersistenceRoundTrip(t *testing.T) {
	st := store(
		verdict(1, "normal", 0.9, scores(0.9, 0.1)),
		verdict(2, "scan", 0.8, scores(0.2, 0.8)),
	)
	s, dir := open(t, st)
	mustPut(t, s, 1, review.StateCorrect, "", "fine")
	mustPut(t, s, 2, review.StateIncorrect, "dos_ddos", "syn flood, not a scan")

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 2 {
		t.Fatalf("expected 2 review files in %s, got %v (%v)", dir, files, err)
	}

	reopened := review.Open(dir, st, nil, nil, quiet)
	for _, want := range []struct {
		id    uint64
		state review.State
		label string
		pred  string
	}{
		{1, review.StateCorrect, "normal", "normal"},
		{2, review.StateIncorrect, "dos_ddos", "scan"},
	} {
		got, ok := reopened.Get(want.id)
		if !ok {
			t.Fatalf("flow %d missing after reload", want.id)
		}
		if got.State != want.state {
			t.Errorf("flow %d state = %q, want %q", want.id, got.State, want.state)
		}
		if got.EffectiveLabel() != want.label {
			t.Errorf("flow %d effective label = %q, want %q", want.id, got.EffectiveLabel(), want.label)
		}
		if got.PredictedClass() != want.pred {
			t.Errorf("flow %d predicted class = %q, want %q", want.id, got.PredictedClass(), want.pred)
		}
		if got.Reviewer != audit.ActorLocal {
			t.Errorf("flow %d reviewer = %q, want %q", want.id, got.Reviewer, audit.ActorLocal)
		}
	}
}

func TestCorruptAndStrayFilesAreSkippedNotFatal(t *testing.T) {
	st := store(verdict(1, "normal", 0.9, scores(0.9, 0.1)))
	s, dir := open(t, st)
	mustPut(t, s, 1, review.StateCorrect, "", "good one")

	if err := os.WriteFile(filepath.Join(dir, "9001.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "9002.json"), []byte(`{"flow_id":0,"state":"correct"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "9003.json"), []byte(`{"flow_id":9003,"state":"probably"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o600); err != nil {
		t.Fatal(err)
	}

	var logged int
	reopened := review.Open(dir, st, nil, nil, func(string, ...any) { logged++ })
	if got := reopened.Stats().Total; got != 1 {
		t.Fatalf("loaded %d review(s), want just the good one", got)
	}
	if _, ok := reopened.Get(1); !ok {
		t.Error("the good review did not survive the bad neighbours")
	}
	if logged == 0 {
		t.Error("skipped files were not logged")
	}
}

// ---- stats ----------------------------------------------------------------

func TestStatsCountsEveryState(t *testing.T) {
	cs := []storage.Classification{}
	for id := uint64(1); id <= 6; id++ {
		cs = append(cs, verdict(id, "normal", 0.8, scores(0.8, 0.2)))
	}
	s, dir := open(t, store(cs...))

	mustPut(t, s, 1, review.StateCorrect, "", "")
	mustPut(t, s, 2, review.StateCorrect, "", "")
	mustPut(t, s, 3, review.StateIncorrect, "scan", "")
	mustPut(t, s, 4, review.StateUnsure, "", "")
	mustPut(t, s, 5, review.StateIgnoredPattern, "", "")
	mustPut(t, s, 6, review.StateUnreviewed, "", "")

	got := s.Stats()
	if got.Total != 6 {
		t.Errorf("total = %d, want 6", got.Total)
	}
	want := map[string]int{"correct": 2, "incorrect": 1, "unsure": 1, "ignored_pattern": 1, "unreviewed": 1}
	for k, v := range want {
		if got.ByState[k] != v {
			t.Errorf("by_state[%s] = %d, want %d", k, got.ByState[k], v)
		}
	}
	if len(got.ByState) != 5 {
		t.Errorf("by_state has %d keys, want all 5 states present", len(got.ByState))
	}
	if got.Terminal != 4 { // 2 correct + 1 incorrect + 1 ignored_pattern
		t.Errorf("terminal = %d, want 4", got.Terminal)
	}
	if got.Open != 2 { // unsure + unreviewed
		t.Errorf("open = %d, want 2", got.Open)
	}
	if got.Labelled != 3 { // 2 correct + 1 incorrect
		t.Errorf("labelled = %d, want 3", got.Labelled)
	}
	if got.Directory != dir {
		t.Errorf("directory = %q, want %q", got.Directory, dir)
	}
}

// ---- list -----------------------------------------------------------------

func TestListFiltersAndOrders(t *testing.T) {
	cs := []storage.Classification{}
	for id := uint64(1); id <= 4; id++ {
		cs = append(cs, verdict(id, "normal", 0.8, scores(0.8, 0.2)))
	}
	s, _ := open(t, store(cs...))
	mustPut(t, s, 1, review.StateCorrect, "", "")
	mustPut(t, s, 2, review.StateIncorrect, "scan", "")
	mustPut(t, s, 3, review.StateUnsure, "", "")
	mustPut(t, s, 4, review.StateIgnoredPattern, "", "")

	if got := len(s.List(review.Filter{})); got != 4 {
		t.Errorf("List(all) = %d, want 4", got)
	}
	if got := s.List(review.Filter{State: review.StateCorrect}); len(got) != 1 || got[0].FlowID != 1 {
		t.Errorf("List(correct) = %+v, want just flow 1", got)
	}
	labelled := s.List(review.Filter{Labelled: true})
	if len(labelled) != 2 {
		t.Fatalf("List(labelled) = %d, want 2 (correct + incorrect)", len(labelled))
	}
	withIgnored := s.List(review.Filter{Labelled: true, IncludeIgnored: true})
	if len(withIgnored) != 3 {
		t.Fatalf("List(labelled+ignored) = %d, want 3", len(withIgnored))
	}
	if got := s.List(review.Filter{Limit: 2}); len(got) != 2 {
		t.Errorf("List(limit 2) = %d rows", len(got))
	}
	// Same UpdatedAt second for all four, so the tiebreak is flow id descending.
	all := s.List(review.Filter{})
	for i := 1; i < len(all); i++ {
		if all[i-1].UpdatedAt == all[i].UpdatedAt && all[i-1].FlowID < all[i].FlowID {
			t.Errorf("order is not total: %d before %d", all[i-1].FlowID, all[i].FlowID)
		}
	}
}

func TestStateOfDefaultsToUnreviewed(t *testing.T) {
	s, _ := open(t, store(verdict(1, "normal", 0.9, scores(0.9, 0.1))))
	if got := s.StateOf(1); got != review.StateUnreviewed {
		t.Errorf("StateOf(unreviewed flow) = %q", got)
	}
	mustPut(t, s, 1, review.StateUnsure, "", "")
	if got := s.StateOf(1); got != review.StateUnsure {
		t.Errorf("StateOf = %q, want unsure", got)
	}
}

// ---- events and audit -----------------------------------------------------

func TestPutPublishesReviewUpdated(t *testing.T) {
	bus := events.New()
	sub := bus.Subscribe(8)
	defer sub.Close()

	dir := t.TempDir()
	auditDir := t.TempDir()
	aud := audit.New(auditDir, quiet)
	s := review.Open(dir, store(verdict(5, "scan", 0.93, scores(0.05, 0.93, 0.02))), bus, aud, quiet)

	if _, err := s.Put(5, review.StateIncorrect, "normal", "the nmap host was ours"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	select {
	case ev := <-sub.C:
		if ev.Type != events.ReviewUpdated {
			t.Fatalf("event type = %q, want ReviewUpdated", ev.Type)
		}
		data, ok := ev.Data.(map[string]any)
		if !ok {
			t.Fatalf("event data is %T, want a map", ev.Data)
		}
		if data["state"] != "incorrect" || data["human_label"] != "normal" || data["predicted_class"] != "scan" {
			t.Errorf("event data = %+v, want the human label alongside the prediction", data)
		}
		if id, _ := data["flow_id"].(uint64); id != 5 {
			t.Errorf("event flow_id = %v, want 5", data["flow_id"])
		}
	case <-time.After(time.Second):
		t.Fatal("no ReviewUpdated event published")
	}

	line, err := os.ReadFile(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var rec audit.Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(line))), &rec); err != nil {
		t.Fatalf("parse audit line %q: %v", line, err)
	}
	if rec.Event != audit.EventReviewUpdated || rec.SubjectType != audit.SubjectReview || rec.Subject != "5" {
		t.Errorf("audit record = %+v, want a review subject for flow 5", rec)
	}
	if !strings.Contains(rec.Detail, "predicted_class=scan") || !strings.Contains(rec.Detail, "human_label=normal") {
		t.Errorf("audit detail %q must carry both the prediction and the human label", rec.Detail)
	}
}

// ---- concurrency ----------------------------------------------------------

// TestConcurrentPutAndRead is the -race guard: the API reviews a flow while the
// SPA polls the queue and the stats strip.
func TestConcurrentPutAndRead(t *testing.T) {
	cs := []storage.Classification{}
	for id := uint64(1); id <= 20; id++ {
		cs = append(cs, verdict(id, "normal", 0.8, scores(0.8, 0.2)))
	}
	st := store(cs...)
	s, _ := open(t, st)

	var wg sync.WaitGroup
	for id := uint64(1); id <= 20; id++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			if _, err := s.Put(id, review.StateUnsure, "", "concurrent"); err != nil {
				t.Errorf("Put(%d): %v", id, err)
			}
		}(id)
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Stats()
			_ = s.List(review.Filter{Limit: 5})
			_ = s.Queue(st.RecentClassifications(100), review.QueueOptions{Sort: review.SortUncertainty})
		}()
	}
	wg.Wait()
	if got := s.Stats().Total; got != 20 {
		t.Errorf("total = %d, want 20", got)
	}
}
