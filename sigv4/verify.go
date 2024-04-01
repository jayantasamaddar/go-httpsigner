package sigv4

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Errors
const (
	ERROR_INCORRECT_FORMAT_HEADER = "incorrectly formatted Authorization header"
	ERROR_INCORRECT_ALGORITHM     = "incorrect algorithm found"
	ERROR_SIGNATURE_MISMATCH      = "computed signature does not match received signature"
)

// All components that make up the `Authorization` header
type AuthHeaders struct {
	Algorithm     string
	Credential    *AuthHeaderCredentials
	SignedHeaders []string
	Signature     string
}

// The Credential comprises of four parts.
type AuthHeaderCredentials struct {
	ACCESS_KEY_ID string // Access Key ID
	Date          string // Format: YYYYMMDD
	Region        string // Region / Data Center (E.g. For AWS: `ap-south-1`)
	Service       string // Name of the service (E.g. `ec2`)
}

type secretretrievalResponse struct {
	SECRET_ACCESS_KEY string `json:"secret_access_key"`
}

// `fmt.Stringer` implementation
func (h *AuthHeaders) String() string {
	return fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		h.Algorithm,
		fmt.Sprintf("%s/%s/%s/%s", h.Credential.ACCESS_KEY_ID, h.Credential.Date, h.Credential.Region, h.Credential.Service),
		strings.Join(h.SignedHeaders, ";"),
		h.Signature,
	)
}

// Intended to be used serverside for verification of the request received
func (s *SigV4) parseAuthHeaders(str string) (*AuthHeaders, error) {
	authHeaders := new(AuthHeaders)
	headers := strings.Split(str, " ")

	// Parse Authorization header
	if len(headers) != 2 {
		return authHeaders, fmt.Errorf(ERROR_INCORRECT_FORMAT_HEADER)
	}
	algorithm, rest := headers[0], headers[1]
	authHeaders.Algorithm = algorithm

	parts := strings.Split(rest, ",")
	if len(parts) != 3 {
		return authHeaders, fmt.Errorf(ERROR_INCORRECT_FORMAT_HEADER)
	}

	for i, v := range parts {
		switch i {
		case 0:
			// Credential
			credentials := strings.Split(v, "=")
			if len(credentials) != 2 || credentials[0] != "Credential" {
				return authHeaders, fmt.Errorf("%s OR %s", ERROR_INCORRECT_FORMAT_HEADER, "Header name 'Credential' incorrect")
			}
			credentialValues := strings.Split(credentials[1], "/")
			if len(credentialValues) != 5 {
				return authHeaders, fmt.Errorf("%s: %s", ERROR_INCORRECT_FORMAT_HEADER, "Credential format error")
			}
			authHeaders.Credential = &AuthHeaderCredentials{
				ACCESS_KEY_ID: credentialValues[0],
				Date:          credentialValues[1],
				Region:        credentialValues[2],
				Service:       credentialValues[3],
			}

		case 1:
			// SignedHeaders
			signedHeaders := strings.Split(v, "=")
			if len(signedHeaders) != 2 || signedHeaders[0] != "SignedHeaders" {
				return authHeaders, fmt.Errorf("%s OR %s", ERROR_INCORRECT_FORMAT_HEADER, "Header name 'SignedHeaders' incorrect")
			}
			authHeaders.SignedHeaders = strings.Split(signedHeaders[1], ";")

		case 2:
			// Signature
			signature := strings.Split(v, "=")
			if len(signature) != 2 || signature[0] != "Signature" {
				return authHeaders, fmt.Errorf("%s OR %s", ERROR_INCORRECT_FORMAT_HEADER, "Header name 'Signature' incorrect")
			}
			authHeaders.Signature = signature[1]
		}
	}

	// // Get `SecretAccessKey` using `secretRetrievalURL`. Once the AuthHeader is successfully parsed, retrieve the secret synchronously
	// Once the AuthHeader is successfully parsed, retrieve the secret synchronously
	secret, err := s.retrieveSecretWithRetry(context.Background(), authHeaders.Credential.ACCESS_KEY_ID)
	if err != nil || secret == "" {
		return nil, fmt.Errorf("failed to retrieve secret (either server endpoint not working or returning unexpected data): %v", err)
	}

	s.env.SECRET_ACCESS_KEY = secret

	return authHeaders, err
}

// RetrieveSecret tries to get the secret access key, retrying up to 3 times in case of failure
func (s *SigV4) retrieveSecretWithRetry(ctx context.Context, accessKeyID string) (string, error) {
	const maxAttempts = 3
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff: sleep for 2^attempt seconds before retrying
			delay := time.Duration(1<<attempt) * time.Second
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		secret, err := s.retrieveSecret(ctx, accessKeyID)
		if err == nil {
			return secret, nil
		}
		lastErr = err
	}

	return "", fmt.Errorf("exceeded maximum attempts: %w", lastErr)
}

// `retrieveSecret` makes one attempt to retrieve the secret access key, observing the provided context's deadline
func (s *SigV4) retrieveSecret(ctx context.Context, accessKeyID string) (string, error) {
	payload, err := json.Marshal(map[string]string{"access_key_id": accessKeyID})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.secretRetrievalURL, bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}

	client := http.Client{Timeout: 15 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(res.Body) // Ignoring error on purpose, main error is from status code
		return "", fmt.Errorf("non-OK HTTP status: %d, body: %s", res.StatusCode, string(bodyBytes))
	}

	var resp secretretrievalResponse
	if err = json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return "", err
	}

	return resp.SECRET_ACCESS_KEY, nil
}

// Verify the signature on the server
func (s *SigV4) VerifySignature(req *http.Request) error {
	// Extract request parameters
	authHeaders, err := s.parseAuthHeaders(req.Header.Get("Authorization"))
	if err != nil {
		return err
	}

	date := req.Header.Get(s.dateHeader())

	if authHeaders.Algorithm != "AWS4-HMAC-SHA256" {
		return fmt.Errorf(ERROR_INCORRECT_ALGORITHM)
	}

	// Prepare canonical request
	clonedReq := req.Clone(context.Background())
	clonedReq.Header.Del("Authorization")   // Remove the Authorization header
	clonedReq.Header.Del("Accept-Encoding") // Remove any attached `Accept-Encoding` headers that maybe attached when http.Client makes RoundTrip

	canonicalRequest, err := s.canonicalRequest(clonedReq)
	if err != nil {
		return err
	}
	req.Body = clonedReq.Body // The req.Body gets read inside the canonicalRequest, and needs to be reassigned

	// Prepare string-to-sign
	stringToSign := s.stringToSign(date, authHeaders.Credential.Region, authHeaders.Credential.Service, canonicalRequest)

	// Derive signing key
	signingKey, err := s.signingKey(s.env.SECRET_ACCESS_KEY, date, authHeaders.Credential.Region, authHeaders.Credential.Service)
	if err != nil {
		return err
	}

	// Calculate computed signature
	computedSignature, err := s.generateSignature(signingKey, stringToSign)
	if err != nil {
		return err
	}

	// Compare computed signature with the received signature
	if computedSignature != authHeaders.Signature {
		return fmt.Errorf(ERROR_SIGNATURE_MISMATCH)
	}

	return nil
}
