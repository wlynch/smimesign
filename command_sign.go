package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/github/smimesign/certstore"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
)

func commandSign() error {
	ctx := context.Background()

	fmt.Fprintln(os.Stderr, os.Args)

	//userIdent, err := findUserIdentity()
	userIdent, err := certstore.NewFulcioIdentity(ctx, stderr)
	if err != nil {
		return errors.Wrap(err, "failed to get identity matching specified user-id")
	}
	if userIdent == nil {
		return fmt.Errorf("could not find identity matching specified user-id: %s", *localUserOpt)
	}

	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropraite. GPG emits this,
	// though GPGSM does not.
	sBeginSigning.emit()

	cert, err := userIdent.Certificate()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity certificate")
	}

	signer, err := userIdent.Signer()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity signer")
	}

	var f io.ReadCloser
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return errors.Wrapf(err, "failed to open message file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = stdin
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, f); err != nil {
		return errors.Wrap(err, "failed to read message from stdin")
	}
	fmt.Fprintln(stderr, dataBuf)

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		return errors.Wrap(err, "failed to create signed data")
	}
	digest, sig, err := sd.Sign([]*x509.Certificate{cert}, signer)
	if err != nil {
		return errors.Wrap(err, "failed to sign message")
	}
	if *detachSignFlag {
		sd.Detached()
	}

	if len(*tsaOpt) > 0 {
		if err = sd.AddTimestamps(*tsaOpt); err != nil {
			return errors.Wrap(err, "failed to add timestamp")
		}
	}

	chain, err := userIdent.CertificateChain()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity certificate chain")
	}
	if chain, err = certsForSignature(chain); err != nil {
		return err
	}
	if err = sd.SetCertificates(chain); err != nil {
		return errors.Wrap(err, "failed to set certificates")
	}

	der, err := sd.ToDER()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signature")
	}

	emitSigCreated(cert, *detachSignFlag)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "SIGNED MESSAGE",
		Bytes: der,
	})
	if *armorFlag {
		_, err = stdout.Write(pemBytes)
	} else {
		_, err = stdout.Write(der)
	}
	if err != nil {
		return errors.New("failed to write signature")
	}

	rClient, err := rekor.NewClient("https://rekor.sigstore.dev")
	if err != nil {
		fmt.Fprintln(stderr, "error creating rekor client: ", err)
		return err
	}
	pk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		fmt.Fprintln(stderr, "error uploading tlog: ", err)
		return err
	}
	pkBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pk,
	})

	commit, err := commitHash(dataBuf.Bytes(), pemBytes)
	if err != nil {
		fmt.Fprintln(stderr, "error generating commit hash: ", err)
		return err
	}
	fmt.Fprintln(stderr, "Predicted commit hash:", commit)

	enc := json.NewEncoder(stderr)
	enc.SetIndent("", " ")

	resp, err := cosign.TLogUpload(ctx, rClient, sig, digest, pkBytes)
	if err != nil {
		fmt.Fprintln(stderr, "error uploading tlog: ", err)
		return err
	}
	enc.Encode(resp)

	// Commit based tlog
	sv := userIdent.SignerVerifier()
	commitSig, err := sv.SignMessage(bytes.NewBufferString(commit))
	if err != nil {
		fmt.Fprintln(stderr, "error signing commit hash: ", err)
		return err
	}
	resp2, err := cosign.TLogUpload(ctx, rClient, commitSig, []byte(commit), pkBytes)
	if err != nil {
		fmt.Fprintln(stderr, "error uploading tlog (commit): ", err)
		return err
	}
	enc.Encode(resp2)

	return nil
}

// findUserIdentity attempts to find an identity to sign with in the certstore
// by checking available identities against the --local-user argument.
func findUserIdentity() (certstore.Identity, error) {
	var (
		email string
		fpr   []byte
	)

	if strings.ContainsRune(*localUserOpt, '@') {
		email = normalizeEmail(*localUserOpt)
	} else {
		fpr = normalizeFingerprint(*localUserOpt)
	}

	if len(email) == 0 && len(fpr) == 0 {
		return nil, fmt.Errorf("bad user-id format: %s", *localUserOpt)
	}

	for _, ident := range idents {
		if cert, err := ident.Certificate(); err == nil && (certHasEmail(cert, email) || certHasFingerprint(cert, fpr)) {
			return ident, nil
		}
	}

	return nil, nil
}

// certsForSignature determines which certificates to include in the signature
// based on the --include-certs option specified by the user.
func certsForSignature(chain []*x509.Certificate) ([]*x509.Certificate, error) {
	include := *includeCertsOpt

	if include < -3 {
		include = -2 // default
	}
	if include > len(chain) {
		include = len(chain)
	}

	switch include {
	case -3:
		for i := len(chain) - 1; i > 0; i-- {
			issuer, cert := chain[i], chain[i-1]

			// remove issuer when cert has AIA extension
			if bytes.Equal(issuer.RawSubject, cert.RawIssuer) && len(cert.IssuingCertificateURL) > 0 {
				chain = chain[0:i]
			}
		}
		return chainWithoutRoot(chain), nil
	case -2:
		return chainWithoutRoot(chain), nil
	case -1:
		return chain, nil
	default:
		return chain[0:include], nil
	}
}

// Returns the provided chain, having removed the root certificate, if present.
// This includes removing the cert itself if the chain is a single self-signed
// cert.
func chainWithoutRoot(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return chain
	}

	lastIdx := len(chain) - 1
	last := chain[lastIdx]

	if bytes.Equal(last.RawIssuer, last.RawSubject) {
		return chain[0:lastIdx]
	}

	return chain
}

func commitHash(data, sig []byte) (string, error) {
	// Precompute commit hash to store in tlog
	obj := &plumbing.MemoryObject{}
	obj.Write(data)
	obj.SetType(plumbing.CommitObject)
	//obj.SetSize(len(data))

	// go-git will compute a hash on decode and preserve that. To work around this,
	// decode into one object then copy everything but the commit into a separate object.
	base := object.Commit{}
	base.Decode(obj)
	c := object.Commit{
		Author:       base.Author,
		Committer:    base.Committer,
		PGPSignature: string(sig),
		Message:      base.Message,
		TreeHash:     base.TreeHash,
		ParentHashes: base.ParentHashes,
	}
	out := &plumbing.MemoryObject{}
	err := c.Encode(out)
	return out.Hash().String(), err
}
