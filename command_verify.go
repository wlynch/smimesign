package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func commandVerify() error {
	fmt.Fprintln(stderr, os.Args, fileArgs)

	sNewSig.emit()

	if len(fileArgs) < 2 {
		return verifyAttached()
	}

	return verifyDetached()
}

func verifyAttached() error {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return errors.Wrapf(err, "failed to open signature file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = stdin
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "failed to read signature")
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = buf.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return errors.Wrap(err, "failed to parse signature")
	}

	// Verify signature
	chains, err := sd.Verify(verifyOpts())
	if err != nil {
		if len(chains) > 0 {
			emitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}

		return errors.Wrap(err, "failed to verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = certHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s\n", fpr)
	emitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	fmt.Fprintf(stderr, "smimesign: Good signature from \"%s\"\n", subj)
	emitTrustFully()

	return nil
}

func verifyDetached() error {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if f, err = os.Open(fileArgs[0]); err != nil {
		return errors.Wrapf(err, "failed to open signature file (%s)", fileArgs[0])
	}
	defer f.Close()

	sig := new(bytes.Buffer)
	if _, err = io.Copy(sig, f); err != nil {
		return errors.Wrap(err, "failed to read signature file")
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(sig.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = sig.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return errors.Wrap(err, "failed to parse signature")
	}

	// Read in signed data
	if fileArgs[1] == "-" {
		f = stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			errors.Wrapf(err, "failed to open message file (%s)", fileArgs[1])
		}
		defer f.Close()
	}

	// Verify signature
	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "failed to read message file")
	}

	chains, err := sd.VerifyDetached(buf.Bytes(), verifyOpts())
	if err != nil {
		if len(chains) > 0 {
			emitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}
		return errors.Wrap(err, "failed to verify signature")
	}

	commit, err := commitHash(buf.Bytes(), sig.Bytes())
	if err != nil {
		fmt.Fprintln(stderr, "error generating commit hash: ", err)
		return err
	}
	fmt.Fprintln(stderr, "searching tlog for commit:", commit)
	tlog, err := findTlog(commit)
	if err != nil {
		fmt.Fprintln(stderr, "error finding tlog: ", err)
		return err
	}
	fmt.Fprintln(stderr, "tlog index:", *tlog.LogIndex)

	var (
		cert = chains[0][0][0]
		fpr  = certHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s | %v\n", fpr, cert.Issuer)
	emitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	fmt.Fprintf(stderr, "smimesign: Good signature from \"%s\" (%v)\n", subj, cert.EmailAddresses)
	emitTrustFully()

	return nil
}

func verifyOpts() x509.VerifyOptions {
	/*
		roots, err := x509.SystemCertPool()
		if err != nil {
			// SystemCertPool isn't implemented for Windows. fall back to mozilla trust
			// store.
			roots, err = gocertifi.CACerts()
			if err != nil {
				// Fall back to an empty store. Verification will likely fail.
				roots = x509.NewCertPool()
			}
		}

		for _, ident := range idents {
			if cert, err := ident.Certificate(); err == nil {
				roots.AddCert(cert)
			}
		}
	*/
	roots := fulcioroots.Get()

	return x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

func findTlog(commit string) (*models.LogEntryAnon, error) {
	ctx := context.Background()
	rClient, err := rekor.NewClient("https://rekor.sigstore.dev")
	if err != nil {
		fmt.Fprintln(stderr, "error creating rekor client: ", err)
		return nil, err
	}

	uuids, err := cosign.FindTLogEntriesByPayload(ctx, rClient, []byte(commit))
	if err != nil {
		return nil, err
	}
	if len(uuids) == 0 {
		return nil, fmt.Errorf("could not find a tlog entry for commit [%s]", commit)
	}
	fmt.Fprintf(stderr, "found %d matching tlog entries\n", len(uuids))

	for _, u := range uuids {
		tlogEntry, err := cosign.GetTlogEntry(ctx, rClient, u)
		if err != nil {
			continue
		}

		// additional tlog verification goes here (need to refactor )

		return tlogEntry, nil
	}
	return nil, errors.New("no tlog entry found")
}
