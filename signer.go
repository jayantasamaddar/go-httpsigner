package httpsigner

import (
	"github.com/jayantasamaddar/go-httpsigner/auth"
)

// Types
const (
	SigV4 int = iota
)

// A Signer has a method `SignHTTPRequest` to signs the HTTP Request. Usually this is deployed Client side.
func NewSigner(constructor func(args ...any) (auth.Signer, error)) (auth.Signer, error) {
	signer, err := constructor()
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// A Verifier has a method `VerifySignature` to validate the HTTP Request signed by a `Signer`. Usually this is deployed Server side.
func NewVerifier(constructor func(args ...any) (auth.Verifier, error)) (auth.Verifier, error) {
	verifier, err := constructor()
	if err != nil {
		return nil, err
	}
	return verifier, nil
}
