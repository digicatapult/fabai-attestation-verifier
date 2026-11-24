//go:build sealtest && !js

package seal_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
	"github.com/digicatapult/fabai-attestation-verifier/internal/fetch"
	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest/synth"
	"github.com/digicatapult/fabai-attestation-verifier/reason"
	"github.com/digicatapult/fabai-attestation-verifier/seal"
)

// replica serves synthetic documents for whatever nonce it's asked for, and
// records every request.
type replica struct {
	live     *synth.Live
	modified atomic.Bool
	mu       sync.Mutex
	requests []*http.Request
	nonces   map[string]int
}

func newReplica(t *testing.T) (*replica, *httptest.Server) {
	t.Helper()
	live, err := synth.NewLive()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(amd.SealtestSetRoots(live.Roots()))
	r := &replica{live: live, nonces: map[string]int{}}
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return r, server
}

func (r *replica) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()
	if req.URL.Path == "/.well-known/hpke-keys" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":["` + hex.EncodeToString(bytes.Repeat([]byte{0xee}, 32)) + `"]}`))
		return
	}
	nonceHex := req.URL.Query().Get("nonce")
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || req.URL.Path != fetch.WellKnownPath {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.nonces[nonceHex]++
	r.mu.Unlock()
	build := r.live.Approved
	if r.modified.Load() {
		build = r.live.Modified
	}
	doc, err := build(nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(doc)
}

func checker(t *testing.T, opts seal.Options) *seal.Checker {
	t.Helper()
	list, err := os.ReadFile("../internal/allowlist/testdata/allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	return seal.SealtestNewChecker(list, true, opts)
}

func TestLiveApproved(t *testing.T) {
	r, server := newReplica(t)
	result := checker(t, seal.Options{}).Check(context.Background(), seal.Target{BaseURL: server.URL})
	if !result.Permitted || result.EntryID != synth.EntryID {
		t.Fatalf("not permitted: %+v", result)
	}
	key, ok := result.SendKey()
	if !ok || !bytes.Equal(key, r.live.HPKEKey()) {
		t.Fatalf("SendKey() = %x, %v", key, ok)
	}
	if _, ok := result.SendKey(); ok {
		t.Error("SendKey returned a key twice")
	}
}

func TestOnlyTheDocumentRequest(t *testing.T) {
	r, server := newReplica(t)
	result := checker(t, seal.Options{}).Check(context.Background(), seal.Target{BaseURL: server.URL, Enclave: "protected.fabai.internal"})
	key, _ := result.SendKey()
	if !bytes.Equal(key, r.live.HPKEKey()) {
		t.Errorf("key %x isn't the document's", key)
	}
	if len(r.requests) != 1 || r.requests[0].URL.Path != fetch.WellKnownPath || r.requests[0].URL.Query().Get("enclave") != "protected.fabai.internal" {
		t.Errorf("requests: %v", r.requests)
	}
}

func TestServerSwappedBetweenSends(t *testing.T) {
	r, server := newReplica(t)
	c := checker(t, seal.Options{})
	first := c.Check(context.Background(), seal.Target{BaseURL: server.URL})
	r.modified.Store(true)
	second := c.Check(context.Background(), seal.Target{BaseURL: server.URL})
	if !first.Permitted {
		t.Fatalf("first send refused: %v", first.Detail.Errors)
	}
	if second.Permitted || second.Ticks.Hardware.Status != seal.Pass || second.Ticks.Software.Status != seal.Fail || second.Ticks.GPU.Status != seal.NotChecked {
		t.Errorf("second send: %+v", second.Ticks)
	}
	if _, ok := second.SendKey(); ok {
		t.Error("the second send got a key")
	}
	if second.Message != "Not sent: this server isn't running the approved software" {
		t.Errorf("message %q", second.Message)
	}
	if second.Detail.Report == nil || second.Detail.Report.Measurement == "" || second.Detail.Report.Policy.Raw == "" {
		t.Error("experts detail lacks the measurement or policy")
	}
}

func TestConcurrentSends(t *testing.T) {
	r, server := newReplica(t)
	c := checker(t, seal.Options{})
	const sends = 8
	var wg sync.WaitGroup
	results := make([]*seal.Result, sends)
	for i := range sends {
		wg.Go(func() { results[i] = c.Check(context.Background(), seal.Target{BaseURL: server.URL}) })
	}
	wg.Wait()
	for i, result := range results {
		if !result.Permitted {
			t.Errorf("send %d refused: %v", i, result.Detail.Errors)
		}
	}
	if len(r.nonces) != sends {
		t.Errorf("%d distinct nonces for %d sends", len(r.nonces), sends)
	}
}

func TestDeadlinePasses(t *testing.T) {
	_, _ = newReplica(t)
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	result := checker(t, seal.Options{Deadline: 100 * time.Millisecond}).Check(context.Background(), seal.Target{BaseURL: slow.URL})
	if result.Permitted || result.Ticks.Hardware.Reason != reason.Timeout {
		t.Errorf("got %+v", result.Ticks)
	}
	if _, ok := result.SendKey(); ok {
		t.Error("a timed-out check returned a key")
	}
}

func TestCollateralUnavailable(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"attestation_unavailable"}`))
	}))
	defer down.Close()
	result := checker(t, seal.Options{}).Check(context.Background(), seal.Target{BaseURL: down.URL})
	if result.Permitted || result.Ticks.Hardware.Reason != reason.BadStatus || result.Ticks.Software.Status != seal.NotChecked {
		t.Errorf("got %+v", result.Ticks)
	}
}

type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) { panic("unexpected state") }

func TestInternalError(t *testing.T) {
	result := checker(t, seal.Options{Transport: panicTransport{}}).Check(context.Background(), seal.Target{BaseURL: "https://replica.example"})
	if result.Permitted || result.Ticks.Hardware.Reason != reason.InternalError {
		t.Errorf("got %+v", result.Ticks)
	}
	if _, ok := result.SendKey(); ok {
		t.Error("an internal error returned a key")
	}
}

func TestTamperedAllowlist(t *testing.T) {
	_, server := newReplica(t)
	list, err := os.ReadFile("../internal/allowlist/testdata/allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	c := seal.New(list, []byte(`{}`), seal.Options{})
	if c.AllowlistError() == nil {
		t.Fatal("an unsigned allowlist was accepted")
	}
	result := c.Check(context.Background(), seal.Target{BaseURL: server.URL})
	if result.Permitted || result.Ticks.Hardware.Reason != reason.AllowlistUnverified || result.Ticks.Software.Status != seal.NotChecked || result.Ticks.GPU.Status != seal.NotChecked {
		t.Errorf("got %+v", result.Ticks)
	}
}
