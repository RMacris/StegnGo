package encryption

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestGenerateSalt tests the salt generation function
func TestGenerateSalt(t *testing.T) {
    tests := []struct {
        length    int
        wantLen   int
        shouldErr bool
    }{
        {16, 16, false},  // Normal case
        {32, 32, false},  // Larger salt
        {0, 0, true},     // Zero length - expect error
        {-1, 0, true},    // Negative length - expect error
    }

    for _, tt := range tests {
        salt, err := GenerateSalt(tt.length)
        if tt.shouldErr {
            if err == nil {
                t.Errorf("GenerateSalt(%d) expected error, got nil", tt.length)
            }
            continue
        }
        if err != nil {
            t.Errorf("GenerateSalt(%d) unexpected error: %v", tt.length, err)
            continue
        }
        if len(salt) != tt.wantLen {
            t.Errorf("GenerateSalt(%d) = %d bytes, want %d bytes", tt.length, len(salt), tt.wantLen)
        }
        salt2, err := GenerateSalt(tt.length)
        if err != nil {
            t.Errorf("GenerateSalt(%d) second call unexpected error: %v", tt.length, err)
            continue
        }
        if bytes.Equal(salt, salt2) {
            t.Errorf("GenerateSalt(%d) produced identical salts", tt.length)
        }
    }
}

// TestDeriveKey tests the key derivation function
func TestDeriveKey(t *testing.T) {
    password := []byte("testpassword")
    salt := make([]byte, 32)
    _, _ = GenerateSalt(32) // Generate a salt for testing

    key := DeriveKey(password, salt)
    
    if len(key) != 32 {
        t.Errorf("DeriveKey() length = %d, want 32", len(key))
    }

    // Test that same input produces same output
    key2 := DeriveKey(password, salt)
    if !bytes.Equal(key, key2) {
        t.Errorf("DeriveKey() produced different keys for same input")
    }

    // Test that different passwords produce different keys
    key3 := DeriveKey([]byte("different"), salt)
    if bytes.Equal(key, key3) {
        t.Errorf("DeriveKey() produced same key for different passwords")
    }

    // Test that different salts produce different keys
    salt2, _ := GenerateSalt(32)
    key4 := DeriveKey(password, salt2)
    if bytes.Equal(key, key4) {
        t.Errorf("DeriveKey() produced same key for different salts")
    }
}

// TestHashAndSalt tests the combined hash and salt function
func TestHashAndSalt(t *testing.T) {
    password := []byte("mypassword")

    hashed, saltHex, err := HashAndSalt(password)
    if err != nil {
        t.Errorf("HashAndSalt() unexpected error: %v", err)
    }

    // Check hash length
    if len(hashed) != 32 {
        t.Errorf("HashAndSalt() hash length = %d, want 32", len(hashed))
    }

    // Check salt length (32 bytes = 64 hex characters)
    if len(saltHex) != 64 {
        t.Errorf("HashAndSalt() salt hex length = %d, want 64", len(saltHex))
    }

    // Verify salt is valid hex
    if _, err := hex.DecodeString(saltHex); err != nil {
        t.Errorf("HashAndSalt() produced invalid hex salt: %v", err)
    }

    // Test that two calls produce different results
    hashed2, saltHex2, _ := HashAndSalt(password)
    if bytes.Equal(hashed, hashed2) && saltHex == saltHex2 {
        t.Errorf("HashAndSalt() produced identical results for two calls")
    }

    // Verify we can derive the same key using the salt
    saltBytes, _ := hex.DecodeString(saltHex)
    derived := DeriveKey(password, saltBytes)
    if !bytes.Equal(hashed, derived) {
        t.Errorf("HashAndSalt() result doesn't match DeriveKey() with same inputs")
    }
}