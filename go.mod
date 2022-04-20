module github.com/github/smimesign

go 1.12

require (
	github.com/go-git/go-git v4.7.0+incompatible
	github.com/go-git/go-git/v5 v5.4.2
	github.com/pborman/getopt v0.0.0-20180811024354-2b5b3bfb099b
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.7.2
	github.com/stretchr/testify v1.7.1
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
	golang.org/x/xerrors v0.0.0-20220411194840-2f41105eb62f
)

replace github.com/sigstore/cosign => ../../sigstore/cosign
