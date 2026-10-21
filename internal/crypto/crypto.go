package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// ResolveKey returns the 32-byte data key used to encrypt god keys at rest.
// KEY_ENCRYPTION_KEY (64 hex chars) is required; the process must fail fast
// without it so god keys are never stored under a weak fallback key.
func ResolveKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return nil, errors.New("KEY_ENCRYPTION_KEY must be set (64 hex chars)")
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, errors.New("KEY_ENCRYPTION_KEY must be 64 hex chars")
	}
	if len(b) != 32 {
		return nil, errors.New("KEY_ENCRYPTION_KEY must be 32 bytes (64 hex chars)")
	}
	return b, nil
}

// Seal encrypts plaintext with AES-256-GCM, output "v1:"+base64(nonce|ciphertext).
func Seal(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "v1:" + base64.StdEncoding.EncodeToString(ct), nil
}

// Open decrypts values produced by Seal.
func Open(key []byte, sealed string) (string, error) {
	if len(sealed) < 3 || sealed[:3] != "v1:" {
		return "", errors.New("unknown ciphertext version")
	}
	raw, err := base64.StdEncoding.DecodeString(sealed[3:])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
