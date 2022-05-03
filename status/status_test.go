package status

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func TestEmit(t *testing.T) {
	b := new(bytes.Buffer)
	status := New(b)
	status.clock = clockwork.NewFakeClockAt(time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC))

	t.Run("Emit", func(t *testing.T) {
		status.Emit(StatusGoodSig)
		assert(t, b, "[GNUPG:] GOODSIG\n")
	})

	t.Run("Emitf", func(t *testing.T) {
		status.emitf(StatusBeginSigning, "fixed")
		status.emitf(StatusGoodSig, "%s", "fmt")
		assert(t, b, "[GNUPG:] BEGIN_SIGNING fixed\n[GNUPG:] GOODSIG fmt\n")
	})

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Raw:                []byte("foo"),
		Subject: pkix.Name{
			CommonName: "bar",
		},
	}

	t.Run("EmitSigCreated", func(t *testing.T) {
		status.EmitSigCreated(cert, true)
		assert(t, b, "[GNUPG:] SIG_CREATED D 19 8 00 1640995200 0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33\n")
	})

	b.Reset()

	t.Run("EmitGoodSig", func(t *testing.T) {
		status.EmitGoodSig([][][]*x509.Certificate{{{cert}}})
		assert(t, b, "[GNUPG:] GOODSIG 0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33 CN=bar\n")
	})

	b.Reset()

	t.Run("EmitbadSig", func(t *testing.T) {
		status.EmitBadSig([][][]*x509.Certificate{{{cert}}})
		assert(t, b, "[GNUPG:] BADSIG 0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33 CN=bar\n")
	})

	b.Reset()

	t.Run("EmitTrustFully", func(t *testing.T) {
		status.EmitTrustFully()
		assert(t, b, "[GNUPG:] TRUST_FULLY 0 shell\n")
	})
}

func assert(t *testing.T, got *bytes.Buffer, want string) {
	t.Helper()
	s := got.String()

	if s != want {
		t.Fatalf("\ngot: \"%s\"\nwant:\"%s\"", got, want)
	}
	got.Reset()
}
