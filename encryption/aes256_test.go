package encryption

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func TestEncryptAESGCM(t *testing.T) {
    password := []byte("mysecretpassword")
    plaintext := []byte("Hello, World!")
    cipherTextHex, saltHex, nonceHex, err := EncryptAESGCM(password, plaintext)
    if err != nil {
        t.Errorf("Encryption failed: %v", err)
    }
    if cipherTextHex == "" || saltHex == "" || nonceHex == "" {
        t.Errorf("Encryption returned empty values")
    }
    // Check salt and nonce lengths
    salt, err := hex.DecodeString(saltHex)
    if err != nil {
        t.Errorf("Failed to decode salt: %v", err)
    }
    if len(salt) != 16 {
        t.Errorf("Salt length is %d, expected 16", len(salt))
    }
    nonce, err := hex.DecodeString(nonceHex)
    if err != nil {
        t.Errorf("Failed to decode nonce: %v", err)
    }
    if len(nonce) != 12 {
        t.Errorf("Nonce length is %d, expected 12", len(nonce))
    }
    // Check that two encryptions produce different outputs
    cipherTextHex2, saltHex2, nonceHex2, err := EncryptAESGCM(password, plaintext)
    if err != nil {
        t.Errorf("Second encryption failed: %v", err)
    }
    if cipherTextHex == cipherTextHex2 || saltHex == saltHex2 || nonceHex == nonceHex2 {
        t.Errorf("Two encryptions produced identical outputs")
    }
}

func TestDecryptAESGCM(t *testing.T) {
    password := []byte("testpassword")
    plaintext := []byte("Hello, world!")

    // Helper function to encrypt data (for test setup)
    getEncrypted := func(plain []byte) (string, string, string, error) {
        salt := make([]byte, 16)
        _, err := rand.Read(salt)
        if err != nil {
            return "", "", "", err
        }
        nonce := make([]byte, 12)
        _, err = rand.Read(nonce)
        if err != nil {
            return "", "", "", err
        }
        key := DeriveKey(password, salt)
        block, _ := aes.NewCipher(key)
        gcm, _ := cipher.NewGCM(block)
        cipherText := gcm.Seal(nil, nonce, plain, nil)
        return hex.EncodeToString(cipherText), hex.EncodeToString(salt), hex.EncodeToString(nonce), nil
    }

    t.Run("successful decryption", func(t *testing.T) {
			cipherTextHex, saltHex, nonceHex, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}
			decrypted, err := DecryptAESGCM(password, cipherTextHex, saltHex, nonceHex)
			if err != nil {
					t.Errorf("Decryption failed: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("Decrypted text does not match original: got %s, want %s", decrypted, plaintext)
			}
    })

    t.Run("wrong password", func(t *testing.T) {
			wrongPassword := []byte("wrongpassword")
			cipherTextHex, saltHex, nonceHex, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}
			_, err = DecryptAESGCM(wrongPassword, cipherTextHex, saltHex, nonceHex)
			if err == nil {
					t.Errorf("Expected error when decrypting with wrong password, got nil")
			}
    })

    t.Run("invalid hex salt", func(t *testing.T) {
			cipherTextHex, _, nonceHex, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}
			invalidSaltHex := "zzz" // invalid hex
			_, err = DecryptAESGCM(password, cipherTextHex, invalidSaltHex, nonceHex)
			if err == nil {
					t.Errorf("Expected error for invalid hex salt, got nil")
			} else if !strings.Contains(err.Error(), "failed to decode salt") {
					t.Errorf("Expected 'failed to decode salt' error, got: %v", err)
			}
    })

    t.Run("invalid hex nonce", func(t *testing.T) {
			cipherTextHex, saltHex, _, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}
			invalidNonceHex := "zzz" // invalid hex
			_, err = DecryptAESGCM(password, cipherTextHex, saltHex, invalidNonceHex)
			if err == nil {
					t.Errorf("Expected error for invalid hex nonce, got nil")
			} else if !strings.Contains(err.Error(), "failed to decode nonce") {
					t.Errorf("Expected 'failed to decode nonce' error, got: %v", err)
			}
    })

    t.Run("invalid hex ciphertext", func(t *testing.T) {
			_, saltHex, nonceHex, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}
			invalidCipherTextHex := "zzz" // invalid hex
			_, err = DecryptAESGCM(password, invalidCipherTextHex, saltHex, nonceHex)
			if err == nil {
					t.Errorf("Expected error for invalid hex ciphertext, got nil")
			} else if !strings.Contains(err.Error(), "failed to decode ciphertext") {
					t.Errorf("Expected 'failed to decode ciphertext' error, got: %v", err)
			}
    })

    t.Run("corrupted ciphertext", func(t *testing.T) {
			cipherTextHex, saltHex, nonceHex, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}
			cipherText, err := hex.DecodeString(cipherTextHex)
			if err != nil {
					t.Fatalf("Failed to decode ciphertext: %v", err)
			}
			if len(cipherText) > 0 {
					cipherText[0] ^= 0x01 // Flip a bit
			}
			corruptedCipherTextHex := hex.EncodeToString(cipherText)
			_, err = DecryptAESGCM(password, corruptedCipherTextHex, saltHex, nonceHex)
			if err == nil {
					t.Errorf("Expected error when decrypting corrupted ciphertext, got nil")
			}
    })

    t.Run("corrupted nonce", func(t *testing.T) {
			cipherTextHex, saltHex, nonceHex, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}
			nonce, err := hex.DecodeString(nonceHex)
			if err != nil {
					t.Fatalf("Failed to decode nonce: %v", err)
			}
			if len(nonce) > 0 {
					nonce[0] ^= 0x01 // Flip a bit
			}
			corruptedNonceHex := hex.EncodeToString(nonce)
			_, err = DecryptAESGCM(password, cipherTextHex, saltHex, corruptedNonceHex)
			if err == nil {
					t.Errorf("Expected error when decrypting with corrupted nonce, got nil")
			}
    })

		t.Run("incorrect_nonce_length", func(t *testing.T) {
			cipherTextHex, saltHex, _, err := getEncrypted(plaintext)
			if err != nil {
					t.Fatalf("Encryption failed: %v", err)
			}

			// Create a nonce that’s too short (11 bytes)
			shortNonce := make([]byte, 11)
			_, err = rand.Read(shortNonce)
			if err != nil {
					t.Fatalf("Failed to generate short nonce: %v", err)
			}
			shortNonceHex := hex.EncodeToString(shortNonce)

			// Attempt decryption with incorrect nonce length
			_, err = DecryptAESGCM(password, cipherTextHex, saltHex, shortNonceHex)
			if err == nil {
					t.Errorf("Expected error for incorrect nonce length, got nil")
			} else if !strings.Contains(err.Error(), "incorrect nonce length") {
					t.Errorf("Expected 'incorrect nonce length' error, got: %v", err)
			}
		})

    t.Run("empty plaintext", func(t *testing.T) {
        emptyPlaintext := []byte{}
        cipherTextHex, saltHex, nonceHex, err := EncryptAESGCM(password, emptyPlaintext)
        if err != nil {
            t.Errorf("Encryption of empty plaintext failed: %v", err)
        }
        decrypted, err := DecryptAESGCM(password, cipherTextHex, saltHex, nonceHex)
        if err != nil {
            t.Errorf("Decryption of empty plaintext failed: %v", err)
        }
        if !bytes.Equal(decrypted, emptyPlaintext) {
            t.Errorf("Decrypted empty plaintext does not match")
        }
    })
}