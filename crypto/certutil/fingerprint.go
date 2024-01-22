package certutil

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

// Fingerprint generates a certificate fingerprint from the given
// certificate instance.
// https://www.rfc-editor.org/rfc/rfc7515#section-4.1.8
//
// The certificate fingerprint can be used to ensure a known server reached by
// TLS communication. The downside of this, is that the finger print will change
// after each certificate changes.
// To be resilient, it is recommended to use the public key fingerprint as a
// reference from `keyutil.Fingerprint()`.
func Fingerprint(cert *x509.Certificate) ([]byte, error) {
	// Check arguments
	if cert == nil {
		return nil, errors.New("certificate must not be nil")
	}

	// Compute the SHA256 checksum of the DER encoded content
	h := sha256.Sum256(cert.Raw)

	// Compute SHA256 checksum of the certificate.
	return h[:], nil
}
