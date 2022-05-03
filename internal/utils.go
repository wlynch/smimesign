package internal

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
)

// certHexFingerprint calculated the hex SHA1 fingerprint of a certificate.
func CertHexFingerprint(cert *x509.Certificate) string {
	return hex.EncodeToString(CertFingerprint(cert))
}

// CertFingerprint calculated the SHA1 fingerprint of a certificate.
func CertFingerprint(cert *x509.Certificate) []byte {
	if len(cert.Raw) == 0 {
		return nil
	}

	fpr := sha1.Sum(cert.Raw)
	return fpr[:]
}
