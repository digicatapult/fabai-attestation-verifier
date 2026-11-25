package fetch

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

func fixedNonce() []byte {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

func TestNoncesNeverRepeat(t *testing.T) {
	const checks = 10000
	seen := make(map[string]bool, checks)
	for range checks {
		nonce, err := NewNonce()
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != NonceSize {
			t.Fatalf("nonce is %d bytes", len(nonce))
		}
		key := string(nonce)
		if seen[key] {
			t.Fatal("a nonce repeated")
		}
		seen[key] = true
	}
}

func TestURL(t *testing.T) {
	nonce := fixedNonce()
	hexNonce := hex.EncodeToString(nonce)
	tests := []struct {
		target  Target
		want    string
		wantErr bool
	}{
		{target: Target{BaseURL: "https://replica.example"}, want: "https://replica.example/.well-known/tinfoil-attestation/v3?nonce=" + hexNonce},
		{target: Target{BaseURL: "https://gw.example/prefix/", Enclave: "protected.fabai.internal"}, want: "https://gw.example/prefix/.well-known/tinfoil-attestation/v3?enclave=protected.fabai.internal&nonce=" + hexNonce},
		{target: Target{BaseURL: "http://10.0.0.5:8443", Enclave: "replica:443"}, want: "http://10.0.0.5:8443/.well-known/tinfoil-attestation/v3?enclave=replica%3A443&nonce=" + hexNonce},
		{target: Target{BaseURL: "ftp://x"}, wantErr: true},
		{target: Target{BaseURL: "https://x/?a=b"}, wantErr: true},
		{target: Target{BaseURL: "https://user@x"}, wantErr: true},
		{target: Target{BaseURL: "https://x", Enclave: "evil.example/../x"}, wantErr: true},
		{target: Target{BaseURL: "https://x", Enclave: "a&nonce=00"}, wantErr: true},
	}
	for _, tt := range tests {
		got, err := tt.target.URL(nonce)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("%+v: got %q, %v; want %q, error %v", tt.target, got, err, tt.want, tt.wantErr)
		}
	}
	if _, err := (Target{BaseURL: "https://x"}).URL(nonce[:31]); err == nil {
		t.Error("a 31-byte nonce was accepted")
	}
}

func fetchFrom(t *testing.T, handler http.HandlerFunc, timeout time.Duration) ([]byte, error) {
	t.Helper()
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Document(ctx, NewClient(server.Client().Transport), Target{BaseURL: server.URL}, fixedNonce())
}

func TestDocumentResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    reason.Code
	}{
		{"collateral unavailable", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"attestation_unavailable"}`))
		}, reason.BadStatus},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example/doc", http.StatusFound)
		}, reason.BadStatus},
		{"wrong content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`{}`))
		}, reason.BadStatus},
		{"oversized, declared", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat(" ", MaxDocumentBytes+1)))
		}, reason.TooLarge},
		{"oversized, chunked", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			for range 3 {
				_, _ = w.Write([]byte(strings.Repeat(" ", MaxDocumentBytes/2)))
				w.(http.Flusher).Flush()
			}
		}, reason.TooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetchFrom(t, tt.handler, 5*time.Second)
			if got := reason.CodeOf(err); got != tt.want {
				t.Errorf("got %v (%v), want %v", got, err, tt.want)
			}
		})
	}
}

func TestDocumentDeadline(t *testing.T) {
	_, err := fetchFrom(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}, 100*time.Millisecond)
	if got := reason.CodeOf(err); got != reason.Timeout {
		t.Errorf("got %v (%v), want timeout", got, err)
	}
}

func TestDocumentRequest(t *testing.T) {
	var got *http.Request
	body, err := fetchFrom(t, func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, 5*time.Second)
	if err != nil || string(body) != `{"ok":true}` {
		t.Fatalf("got %q, %v", body, err)
	}
	if got.Method != http.MethodGet || got.URL.Path != WellKnownPath || got.URL.Query().Get("nonce") != hex.EncodeToString(fixedNonce()) || got.ContentLength > 0 {
		t.Errorf("unexpected request %s %s", got.Method, got.URL)
	}
}
