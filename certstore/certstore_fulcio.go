package certstore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
)

type FulcioIdentity struct {
	sv     *sign.SignerVerifier
	stderr io.Writer
}

func NewFulcioIdentity(ctx context.Context, w io.Writer) (*FulcioIdentity, error) {
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", sign.KeyOpts{
		FulcioURL:    "https://fulcio.sigstore.dev",
		OIDCIssuer:   "https://oauth2.sigstore.dev/auth",
		OIDCClientID: "sigstore",
	})
	if err != nil {
		return nil, err
	}
	return &FulcioIdentity{
		sv:     sv,
		stderr: w,
	}, nil
}

// Certificate gets the identity's certificate.
func (i *FulcioIdentity) Certificate() (*x509.Certificate, error) {
	//fmt.Printf("%T %+v\n", i.sv.SignerVerifier, i.sv.SignerVerifier)
	//fmt.Println(string(i.sv.Cert))
	//fmt.Fprintln(i.stderr, string(i.sv.Cert))

	p, _ := pem.Decode(i.sv.Cert)
	cert, err := x509.ParseCertificate(p.Bytes)
	fmt.Fprintf(i.stderr, "%+v\n", cert)
	return cert, err
}

// CertificateChain attempts to get the identity's full certificate chain.
func (i *FulcioIdentity) CertificateChain() ([]*x509.Certificate, error) {
	fmt.Fprintln(i.stderr, string(i.sv.Chain))
	p, _ := pem.Decode(i.sv.Chain)
	chain, err := x509.ParseCertificates(p.Bytes)
	if err != nil {
		return nil, err
	}
	// the cert itself needs to be appended to the chain
	cert, err := i.Certificate()
	if err != nil {
		return nil, err
	}

	return append([]*x509.Certificate{cert}, chain...), nil

}

// Signer gets a crypto.Signer that uses the identity's private key.
func (i *FulcioIdentity) Signer() (crypto.Signer, error) {
	s, ok := i.sv.SignerVerifier.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("could not use signer %T as crypto.Signer", i.sv.SignerVerifier)
	}
	return s, nil
}

// Delete deletes this identity from the system.
func (i *FulcioIdentity) Delete() error {
	// Does nothing - keys are ephemeral
	return nil
}

// Close any manually managed memory held by the Identity.
func (i *FulcioIdentity) Close() {
	return
}
