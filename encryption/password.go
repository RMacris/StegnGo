package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

func GenerateSalt(length int) ([]byte, error) {
    if length <= 0 {
        return nil, fmt.Errorf("salt length must be positive, got %d", length)
    }
    salt := make([]byte, length)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, fmt.Errorf("failed to generate salt: %v", err)
    }
    return salt, nil
}

// DeriveKey derives a 32-byte key from the given password and salt using an expensive Argon2 configuration.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 6, 256*1024, 8, 32) // 6 iterations, 256MB RAM, 8 threads, 32-byte key
}

// HashAndSalt hashes a password using Argon2 with a randomly generated salt.
// Returns the hashed password as bytes and the salt as a hex-encoded string.
func HashAndSalt(password []byte) ([]byte, string, error) {
	// Generate a random salt (32 bytes for added security)
	salt, err := GenerateSalt(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derive the key using Argon2 with a very high computational cost
	hashedPassword := DeriveKey(password, salt)

	// Convert the salt to a hex-encoded string
	saltHex := hex.EncodeToString(salt)

	return hashedPassword, saltHex, nil
}