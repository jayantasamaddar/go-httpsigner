package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Hash a data string using SHA-256 and returns the checksum.
func Hash(b []byte) string {
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// Returns a HMAC hash
func HmacSHA256(key []byte, data string) ([]byte, error) {
	hmac := hmac.New(sha256.New, key)
	_, err := hmac.Write([]byte(data))
	return hmac.Sum(nil), err
}
