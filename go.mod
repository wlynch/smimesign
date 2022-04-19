module github.com/github/smimesign

go 1.12

require (
	github.com/certifi/gocertifi v0.0.0-20200922220541-2c3bb06c6054
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pborman/getopt v0.0.0-20180811024354-2b5b3bfb099b
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.7.2
	github.com/stretchr/testify v1.7.1
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	golang.org/x/xerrors v0.0.0-20220411194840-2f41105eb62f
	google.golang.org/api v0.74.0
)

replace github.com/sigstore/cosign => ../../sigstore/cosign
