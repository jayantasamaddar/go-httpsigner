package httpsigner

import (
	"os"
	"testing"

	"github.com/jayantasamaddar/go-httpsigner/auth"
	"github.com/jayantasamaddar/go-httpsigner/sigv4"
)

// Signer is usually deployed client-side
func Test_Signer(t *testing.T) {
	os.Setenv("ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	os.Setenv("SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	os.Setenv("REGION", "ap-south-1")

	_, err := NewSigner(func(args ...any) (auth.Signer, error) {
		return sigv4.NewSigV4Signer("SYM", "sym", "certificatemanager", &sigv4.SigV4EnvConfig{
			ACCESS_KEY_ID:     os.Getenv("ACCESS_KEY_ID"),
			SECRET_ACCESS_KEY: os.Getenv("SECRET_ACCESS_KEY"),
			REGION:            os.Getenv("REGION"),
		}, false)
	})

	if err != nil {
		t.Error(err)
	}
}

// Verifier is usually deployed server-side
func Test_Verifier(t *testing.T) {
	_, err := NewVerifier(func(args ...any) (auth.Verifier, error) {
		return sigv4.NewSigV4Verifier("SYM", "sym", "certificatemanager", "http://validate.127.0.0.1.sslip.io/api/secret")
	})

	if err != nil {
		t.Error(err)
	}
}
