package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// EncryptAESGCM encrypts plaintext using AES-GCM with a derived key from the password.
func EncryptAESGCM(password, plaintext []byte) (cipherTextHex, saltHex, nonceHex string, err error) {
	// Generate a random salt (16 bytes)
	salt, err := GenerateSalt(16)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derive a 32-byte key using PBKDF2
	key := DeriveKey(password, salt) // 100,000 iterations for security

	// Generate a random nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create GCM mode: %v", err)
	}

	// Encrypt the data using AES-GCM
	cipherText := gcm.Seal(nil, nonce, plaintext, nil)

	// Return hex-encoded ciphertext, salt, and nonce
	return hex.EncodeToString(cipherText), hex.EncodeToString(salt), hex.EncodeToString(nonce), nil
}


func DecryptAESGCM(password []byte, cipherTextHex, saltHex, nonceHex string) ([]byte, error) {
	// Decode hex-encoded salt
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
			return nil, fmt.Errorf("failed to decode salt: %v", err)
	}

	// Decode hex-encoded nonce
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
			return nil, fmt.Errorf("failed to decode nonce: %v", err)
	}

	// Validate nonce length (must be 12 bytes for AES-GCM)
	if len(nonce) != 12 {
			return nil, fmt.Errorf("incorrect nonce length: got %d, expected 12", len(nonce))
	}

	// Decode hex-encoded ciphertext
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
			return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	// Derive the encryption key using PBKDF2
	key := DeriveKey(password, salt)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Initialize GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
			return nil, fmt.Errorf("failed to create GCM mode: %v", err)
	}

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}
