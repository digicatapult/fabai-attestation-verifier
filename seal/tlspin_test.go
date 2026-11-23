package seal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// expiredServer is a TLS server whose self-signed certificate expired an
// hour after "boot", like a replica in tls-mode self-signed.
func expiredServer(t *testing.T, requests *atomic.Int32) (*httptest.Server, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boot := time.Now().Add(-48 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    boot,
		NotAfter:     boot.Add(time.Hour),
		DNSNames:     []string{"replica.example"},
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return server, pin[:]
}

func get(t *testing.T, server *httptest.Server, pin []byte) error {
	t.Helper()
	config, err := PinnedTLSConfig(pin, "replica.example")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
	resp, err := client.Get(server.URL)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestPinnedTLSAcceptsExpiredCertificate(t *testing.T) {
	var requests atomic.Int32
	server, pin := expiredServer(t, &requests)
	if err := get(t, server, pin); err != nil {
		t.Fatalf("matching pin refused: %v", err)
	}
	if requests.Load() != 1 {
		t.Errorf("server saw %d requests", requests.Load())
	}
}

func TestPinnedTLSMismatchSendsNothing(t *testing.T) {
	var requests atomic.Int32
	server, pin := expiredServer(t, &requests)
	wrong := append([]byte(nil), pin...)
	wrong[0] ^= 1
	if err := get(t, server, wrong); err == nil {
		t.Fatal("a mismatched pin was accepted")
	}
	if requests.Load() != 0 {
		t.Errorf("server saw %d requests", requests.Load())
	}
}

func TestPinnedTLSRejectsBadPin(t *testing.T) {
	if _, err := PinnedTLSConfig(make([]byte, 31), "x"); err == nil {
		t.Error("a 31-byte pin was accepted")
	}
}
