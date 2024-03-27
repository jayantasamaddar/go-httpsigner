package sigv4

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/jayantasamaddar/go-httpsigner/utils"
)

// # (1) Create the Canonical Request
//
// ----------------------------------------
//
// The `CanonicalRequest` is built out of 6 parameters joined by a new line character ("\n") after each paramter.
//
// (a) `HTTPMethod`: The HTTP method, such as GET, PUT, HEAD, and DELETE.
//
// (b) `CanonicalURI`: The URI-encoded version of the absolute path component URI, starting with the "/" that follows the domain name
// and up to the end of the string or to the question mark character ('?') if you have query string parameters.
// If the absolute path is empty, use a forward slash character (/).
// The URI in the following example: http://s3.amazonaws.com/examplebucket/myphoto.jpg,
//
//	/examplebucket/myphoto.jpg,
//
// is the absolute path and you don't encode the "/" in the absolute path:
//
// (c) `CanonicalQueryString`: The URI-encoded query string parameters. You URI-encode each name and values individually.
// You must also sort the parameters in the canonical query string alphabetically by key name.
// The sorting occurs after encoding. In this URI example: http://s3.amazonaws.com/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=2
//
// The canonical query string is as follows (line breaks are added to this example for readability):
//
//	UriEncode("marker")+"="+UriEncode("someMarker")+"&"+
//	UriEncode("max-keys")+"="+UriEncode("20") + "&" +
//	UriEncode("prefix")+"="+UriEncode("somePrefix")
//
// When a request targets a subresource, the corresponding query parameter value will be an empty string ("").
// For example, the following URI identifies the ACL subresource on the examplebucket bucket:
//
// E.g. http://s3.amazonaws.com/examplebucket?acl
//
// The `CanonicalQueryString` in this case is as follows:
//
//	UriEncode("acl") + "=" + ""
//
// If the URI does not include a '?', there is no query string in the request, and you set the canonical query string to an empty string ("").
// You will still need to include the "\n".
//
// (d) `CanonicalHeaders`: A list of request headers with their values.
// Individual header name and value pairs are separated by the newline character ("\n").
// The following is an example of a canonicalheader:
//
//	Lowercase(<HeaderName1>)+":"+Trim(<value>)+"\n"
//	Lowercase(<HeaderName2>)+":"+Trim(<value>)+"\n"
//
// # Example:
//
//	host:s3.amazonaws.com
//	x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//	x-amz-date:20130708T220855Z
//
// (e) `SignedHeaders`: An alphabetically sorted, semicolon-separated list of lowercase request header names. The request headers in the list are the same headers that you included in the `CanonicalHeaders` string.
// For example, for the previous example, the value of SignedHeaders would be as follows:
//
//	host;x-amz-content-sha256;x-amz-date
//
// (f) `HashedPayload`: A string created using the payload in the body of the HTTP request as input to a hash function.
//
//	Hex(SHA256Hash(<payload>)
//
// This string uses lowercase hexadecimal characters. If there is no payload in the request, you compute a hash of the empty string as follows:
//
//	Hex(SHA256Hash(""))
func (s *SigV4) canonicalRequest(req *http.Request) (string, error) {
	ch, sh := s.getCanonicalAndSignedHeaders(req)

	// Buffer to store request body
	var buf bytes.Buffer
	if req.Body != nil {
		// Read the request body and capture it into a buffer
		teeReader := io.TeeReader(req.Body, &buf)
		_, err := io.ReadAll(teeReader)
		if err != nil {
			return "", nil
		}

		// Reset the request body to the captured buffer
		req.Body = io.NopCloser(&buf)
	}
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		s.getCanonicalURI(req),
		s.getCanonicalQueryString(req),
		ch,
		sh,
		utils.Hash(buf.Bytes()),
	), nil
}

// (b) `getCanonicalURI` builds a canonical URI following the SigV4 Algorithm
func (s *SigV4) getCanonicalURI(req *http.Request) string {
	// Extract the absolute path from the request URL
	absPath := req.URL.Path

	// If the absolute path is empty, use a forward slash character "/"
	if absPath == "" {
		absPath = "/"
	}

	// Return the encoded absolute path according to custom URI encoding rules
	return sigV4UriEncode(absPath)
}

// # (b1) `sigV4UriEncode` takes an absolute path string and does an URI encoding based on the SigV4 algorithm
//
// URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
//   - The space character is a reserved character and must be encoded as "%20" (and not as "+").
//   - Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
//   - Letters in the hexadecimal value must be uppercase, for example "%1A".
//   - Encode the forward slash character, '/', everywhere except in the object key name. For example, if the object key name is photos/Jan/sample.jpg, the forward slash in the key name is not encoded.
func sigV4UriEncode(s string) string {
	var encoded strings.Builder

	for _, r := range s {
		if isUnreserved(r) || r == '/' {
			encoded.WriteRune(r)
		} else if r == ' ' {
			encoded.WriteString("%20")
		} else {
			encoded.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}

	return encoded.String()
}

// # (b1a) `isUnreserved` checks if unicode character is unreserved for the `sigV4UriEncode`. Every other character is to be UriEncoded.
func isUnreserved(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_' || r == '~'
}

// # (c) Get the `CanonicalQueryString` to be used to create the Canonical Request. Sorted by query parameter.
func (s *SigV4) getCanonicalQueryString(req *http.Request) string {
	// Extract query string from the URL
	queryString := req.URL.RawQuery

	// Parse the query string into a map
	queryParams, err := url.ParseQuery(queryString)
	if err != nil {
		panic(err)
	}

	// Sort query parameters alphabetically by key
	var keys []string
	for key := range queryParams {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Construct canonical query string
	var canonicalParams []string
	for _, key := range keys {
		values := queryParams[key]
		for _, value := range values {
			encodedKey := url.QueryEscape(key)
			encodedValue := url.QueryEscape(value)
			canonicalParams = append(canonicalParams, encodedKey+"="+encodedValue)
		}
	}

	// Concatenate query parameters with "&" separator
	canonicalQueryString := strings.Join(canonicalParams, "&")
	return canonicalQueryString
}

// # (d) Get Canonical Headers and (e) Signed Headers as two return values
func (s *SigV4) getCanonicalAndSignedHeaders(req *http.Request) (canonicalHeaders, signedHeaders string) {
	req.Header.Set("Host", req.Host)
	ch := []string{}
	sh := []string{}
	for key, header := range req.Header {
		ch = append(ch, fmt.Sprintf("%s:%s", strings.ToLower(key), strings.TrimSpace(strings.Join(header, ","))))
		sh = append(sh, strings.ToLower(key))
	}

	// Sort the CanonicalHeaders and SignedHeaders
	sort.Strings(ch)
	sort.Strings(sh)

	return strings.Join(ch, "\n"), strings.Join(sh, ";")
}
