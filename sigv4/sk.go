package sigv4

import (
	"fmt"
	"time"

	"github.com/jayantasamaddar/go-httpsigner/utils"
)

// (3) Derive the Signing Key
func (s *SigV4) signingKey(accessKey, dateString, region, service string) ([]byte, error) {
	// Parse the date string
	parsedTime, err := time.Parse(time.RFC3339Nano, dateString)
	if err != nil {
		return []byte{}, err
	}
	//Extract year, month, and day
	YYYY, MM, DD := parsedTime.Date()
	key := []byte("AWS4" + accessKey)

	key, _ = utils.HmacSHA256(key, fmt.Sprintf("%d%d%d", YYYY, MM, DD)) // (a) DateKey
	key, _ = utils.HmacSHA256(key, region)                              // (b) DateRegionKey
	key, _ = utils.HmacSHA256(key, service)                             // (c) DateRegionServiceKey
	key, _ = utils.HmacSHA256(key, "aws4_request")                      // (d) SigningKey

	return key, nil
}
