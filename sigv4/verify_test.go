package sigv4

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func Test_VerifySignature(t *testing.T) {
	os.Setenv("ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	os.Setenv("SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	os.Setenv("REGION", "ap-south-1")

	urls := []string{
		"http://s3.amazonaws.com/examplebucket/myphoto.jpg?prefix=somePrefix&marker=someMarker&max-keys=2",
		"http://validate.127.0.0.1.sslip.io/api/cmagent",
		"http://s3.amazonaws.com/examplebucket?prefix=somePrefix",
	}

	type secretRequest struct {
		ACCESS_KEY_ID string `json:"access_key_id"`
	}

	// Set up a mock server to handle secretRetrieval
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Respond with a sample response
			w.WriteHeader(http.StatusOK)

			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal("Could not read request body for secret retrieval")
			}

			// Access the body and retrieve the `access_key_id`
			var accessKey secretRequest
			err = json.Unmarshal(b, &accessKey)
			if err != nil {
				t.Fatal("Could not unmarshall request for secret retrieval")
			}

			// Consider verification is done

			// Send response back
			b, err = json.Marshal(map[string]string{"secret_access_key": os.Getenv("SECRET_ACCESS_KEY")})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(b)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	signer, _ := NewSigV4Signer("SYM", "sym", "certificatemanager", &SigV4EnvConfig{
		ACCESS_KEY_ID:     os.Getenv("ACCESS_KEY_ID"),
		SECRET_ACCESS_KEY: os.Getenv("SECRET_ACCESS_KEY"),
		REGION:            os.Getenv("REGION"),
	}, false)

	verifier, err := NewSigV4Verifier("SYM", "sym", "certificatemanager", mockServer.URL)
	if err != nil {
		t.Fatal(err)
		return
	}

	for _, url := range urls {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Content-Type", "application/json")

		err := signer.SignHTTPRequest(req)
		if err != nil {
			t.Error(err)
			return
		}

		err = verifier.VerifySignature(req)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("Tested against URL: %q\n", url)
	}
}
