package seal

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
)

// PinnedTLSConfig returns a TLS client config for a native client connecting
// directly to a replica. It accepts the connection only if the SHA-256 of the
// presented leaf's DER SubjectPublicKeyInfo equals pin, the "tls" key from a
// check made with ChannelTLS. The leaf's chain and validity period are
// ignored: in tls-mode self-signed, the replica's certificate expires an hour
// after boot. A mismatch fails the handshake, before any request is written.
func PinnedTLSConfig(pin []byte, serverName string) (*tls.Config, error) {
	if len(pin) != sha256.Size {
		return nil, fmt.Errorf("TLS pin must be %d bytes, got %d", sha256.Size, len(pin))
	}
	want := append([]byte(nil), pin...)
	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		// Certificate validation is replaced by the attested SPKI pin.
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection checks the pin.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errors.New("server's TLS key isn't the attested one")
			}
			return nil
		},
	}, nil
}
