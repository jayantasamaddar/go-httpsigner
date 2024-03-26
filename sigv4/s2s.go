package sigv4

import (
	"fmt"

	"github.com/jayantasamaddar/go-httpsigner/utils"
)

// # Create the stringToSign
// ------------------------------
//
// stringToSign is built out of four parameters, joined by a newline character ("\n") after each parameter.
//  1. `Algorithm`: The algorithm used to create the hash of the canonical request. For SHA-256, the algorithm is `AWS4-HMAC-SHA256`.
//  2. `RequestDateTime`: The date and time used in the credential scope. This value is the current UTC time in ISO 8601 format (for example, 20130524T000000Z).
//  3. `CredentialScope`: The credential scope. This restricts the resulting signature to the specified Region and service.
//     The string has the following format: YYYYMMDD/region/service/aws4_request.
//  4. `HashedCanonicalRequest`: The hash of the canonical request using the same algorithm that you used to create the hash of the payload.
func (s *SigV4) stringToSign(dateString, region, service, canonicalRequest string) string {

	// Get the RFC339 formatted Date String from the Request Header

	return fmt.Sprintf("%s\n%s\n%s\n%s",
		"AWS4-HMAC-SHA256",
		dateString,
		s.getCredentialScope(dateString, region, service),
		utils.Hash([]byte(canonicalRequest)),
	)
}
