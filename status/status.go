// Package status implements gnupg's "status protocol". When the --status-fd argument
// is passed, gpg will output machine-readable status updates to that fd.
// Details on the "protocol" can be found at https://github.com/gpg/gnupg/blob/master/doc/DETAILS#format-of-the-status-fd-output
package status

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/github/smimesign/internal"
	"github.com/jonboulle/clockwork"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

type status string

const (
	prefix = "[GNUPG:] "

	// BEGIN_SIGNING
	//   Mark the start of the actual signing process. This may be used as an
	//   indication that all requested secret keys are ready for use.
	StatusBeginSigning status = "BEGIN_SIGNING"

	// SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <keyfpr>
	//   A signature has been created using these parameters.
	//   Values for type <type> are:
	//     - D :: detached
	//     - C :: cleartext
	//     - S :: standard
	//   (only the first character should be checked)
	//
	//   <class> are 2 hex digits with the OpenPGP signature class.
	//
	//   Note, that TIMESTAMP may either be a number of seconds since Epoch
	//   or an ISO 8601 string which can be detected by the presence of the
	//   letter 'T'.
	StatusSigCreated status = "SIG_CREATED"

	// NEWSIG [<signers_uid>]
	//   Is issued right before a signature verification starts.  This is
	//   useful to define a context for parsing ERROR status messages.
	//   arguments are currently defined.  If SIGNERS_UID is given and is
	//   not "-" this is the percent escape value of the OpenPGP Signer's
	//   User ID signature sub-packet.
	StatusNewSig status = "NEWSIG"

	// GOODSIG  <long_keyid_or_fpr>  <username>
	//   The signature with the keyid is good.  For each signature only one
	//   of the codes GOODSIG, BADSIG, EXPSIG, EXPKEYSIG, REVKEYSIG or
	//   ERRSIG will be emitted.  In the past they were used as a marker
	//   for a new signature; new code should use the NEWSIG status
	//   instead.  The username is the primary one encoded in UTF-8 and %XX
	//   escaped. The fingerprint may be used instead of the long keyid if
	//   it is available.  This is the case with CMS and might eventually
	//   also be available for OpenPGP.
	StatusGoodSig status = "GOODSIG"

	// BADSIG <long_keyid_or_fpr> <username>
	//   The signature with the keyid has not been verified okay. The username is
	//   the primary one encoded in UTF-8 and %XX escaped. The fingerprint may be
	//   used instead of the long keyid if it is available. This is the case with
	//   CMS and might eventually also be available for OpenPGP.
	StatusBadSig status = "BADSIG"

	// ERRSIG <keyid> <pkalgo> <hashalgo> <sig_class> <time> <rc>
	//
	//   It was not possible to check the signature. This may be caused by a
	//   missing public key or an unsupported algorithm. A RC of 4 indicates
	//   unknown algorithm, a 9 indicates a missing public key. The other fields
	//   give more information about this signature. sig_class is a 2 byte hex-
	//   value. The fingerprint may be used instead of the keyid if it is
	//   available. This is the case with gpgsm and might eventually also be
	//  available for OpenPGP.
	//
	//   Note, that TIME may either be the number of seconds since Epoch or an ISO
	//   8601 string. The latter can be detected by the presence of the letter
	//   ‘T’.
	StatusErrSig status = "ERRSIG"

	// TRUST_
	//   These are several similar status codes:
	//
	//   - TRUST_UNDEFINED <error_token>
	//   - TRUST_NEVER     <error_token>
	//   - TRUST_MARGINAL  [0  [<validation_model>]]
	//   - TRUST_FULLY     [0  [<validation_model>]]
	//   - TRUST_ULTIMATE  [0  [<validation_model>]]
	//
	//   For good signatures one of these status lines are emitted to
	//   indicate the validity of the key used to create the signature.
	//   The error token values are currently only emitted by gpgsm.
	//
	//   VALIDATION_MODEL describes the algorithm used to check the
	//   validity of the key.  The defaults are the standard Web of Trust
	//   model for gpg and the standard X.509 model for gpgsm.  The
	//   defined values are
	//
	//      - pgp   :: The standard PGP WoT.
	//      - shell :: The standard X.509 model.
	//      - chain :: The chain model.
	//      - steed :: The STEED model.
	//      - tofu  :: The TOFU model
	//
	//   Note that the term =TRUST_= in the status names is used for
	//   historic reasons; we now speak of validity.
	StatusTrustFully status = "TRUST_FULLY"
)

// Writer implements a GPG writer, with utilities for formatting common details
// like cert data, etc.
type Writer struct {
	statusFile io.Writer
	clock      clockwork.Clock
}

// New creates a new Writer that outputs any status data to the given
// io.Writer.
func New(w io.Writer) *Writer {
	return &Writer{
		statusFile: w,
		clock:      clockwork.NewRealClock(),
	}
}

// NewFromFD creates a new Writer from the given file descriptor
// (i.e. the value from --status-fd).
func NewFromFD(fd int) *Writer {
	const (
		unixStdout = 1
		unixStderr = 2
	)

	w := &Writer{
		clock: clockwork.NewRealClock(),
	}
	// Even though Windows uses different numbers, we always equate 1/2 with
	// stdout/stderr because Git always passes `--status-fd=1`.
	switch {
	case fd < 0:
		w.statusFile = ioutil.Discard
	case fd == unixStdout:
		w.statusFile = os.Stdout
	case fd == unixStderr:
		w.statusFile = os.Stderr
	default:
		// TODO: debugging output if this fails
		w.statusFile = os.NewFile(uintptr(fd), "status")
	}
	return w
}

func (w *Writer) emitf(s status, format string, args ...interface{}) {
	fmt.Fprint(w.statusFile, prefix)
	fmt.Fprint(w.statusFile, string(s))
	fmt.Fprintf(w.statusFile, " "+format+"\n", args...)
}

func (w *Writer) Emit(s status) {
	fmt.Fprintln(w.statusFile, prefix+string(s))
}

func (w *Writer) EmitSigCreated(cert *x509.Certificate, isDetached bool) {
	// SIG_CREATED arguments
	var (
		sigType                    string
		pkAlgo, hashAlgo, sigClass byte
		now                        int64
		fpr                        string
	)

	if isDetached {
		sigType = "D"
	} else {
		sigType = "S"
	}

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		pkAlgo = byte(packet.PubKeyAlgoRSA)
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		pkAlgo = byte(packet.PubKeyAlgoECDSA)
	}

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA1)
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA256)
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA384)
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA512)
	}

	// gpgsm seems to always use 0x00
	sigClass = 0
	now = w.clock.Now().Unix()
	fpr = internal.CertHexFingerprint(cert)

	w.emitf(StatusSigCreated, "%s %d %d %02x %d %s", sigType, pkAlgo, hashAlgo, sigClass, now, fpr)
}

func (w *Writer) EmitGoodSig(chains [][][]*x509.Certificate) {
	cert := chains[0][0][0]
	subj := cert.Subject.String()
	fpr := internal.CertHexFingerprint(cert)

	w.emitf(StatusGoodSig, "%s %s", fpr, subj)
}

func (w *Writer) EmitBadSig(chains [][][]*x509.Certificate) {
	cert := chains[0][0][0]
	subj := cert.Subject.String()
	fpr := internal.CertHexFingerprint(cert)

	w.emitf(StatusBadSig, "%s %s", fpr, subj)
}

func (w *Writer) EmitTrustFully() {
	w.emitf(StatusTrustFully, "0 shell")
}
