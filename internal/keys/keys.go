package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const prefix = "sevsh_"

// Generate returns a new plaintext sub-key (sevsh_<48 hex chars>).
func Generate() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// Hash returns the hex SHA-256 of the plaintext key.
func Hash(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// Prefix returns the first 12 chars for log correlation (no secret material).
func Prefix(plaintext string) string {
	t := strings.TrimSpace(plaintext)
	if len(t) > 12 {
		return t[:12]
	}
	return t
}

// Normalize strips an optional "Bearer " scheme and whitespace.
func Normalize(h string) string {
	h = strings.TrimSpace(h)
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return h
}
