package auth

import "net/http"

// Signer interface to be implemented by any signing mechanism.
type Signer interface {
	SignHTTPRequest(req *http.Request) error
}

// Verifier interface to be implemented by any verification mechanism.
type Verifier interface {
	VerifySignature(req *http.Request) error
}
