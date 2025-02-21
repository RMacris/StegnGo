package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ToBytes serializes any Go data type into a byte slice.
func ToBytes(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(data); err != nil {
		return nil, fmt.Errorf("error encoding data to bytes: %v", err)
	}
	return buf.Bytes(), nil
}

func IsValidDirectory(path string) bool {
	// If the path is empty, treat it as the current directory (".")
	if path == "" {
		path = "."
	}

	// Clean the path to remove redundant elements
	cleanedPath := filepath.Clean(path)

	// Check if the cleaned path exists and is a directory
	info, err := os.Stat(cleanedPath)
	return err == nil && info.IsDir()
}

// SanitizeFileName removes special characters and ensures no file extension remains.
func SanitizeFileName(name string) string {
	// Remove any characters that are not alphanumeric, spaces, hyphens, or underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9 _-]`)
	sanitized := re.ReplaceAllString(name, "")

	// Remove any trailing dots (to prevent file extensions)
	sanitized = strings.TrimRight(sanitized, ".")

	return sanitized
}

// SerializePayload converts a Payload struct into JSON-encoded bytes.
func SerializePayload(p Payload) ([]byte, error) {
	serialized, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %v", err)
	}
	return serialized, nil
}

// DeserializePayload converts JSON-encoded bytes back into a Payload struct.
func DeserializePayload(serialized []byte) (*Payload, error) {
	var p Payload
	err := json.Unmarshal(serialized, &p)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize payload: %v", err)
	}
	return &p, nil
}

//concat by . and return
func AddCypherMetadata(saltHex, nonceHex, cipherTextStr string) string {
	return saltHex + "." + nonceHex + "." + cipherTextStr
}

func ExtractCypherMetadata(metadata string) (string, string, string) {
	parts := strings.Split(metadata, ".")
	return parts[0], parts[1], parts[2]
}

func IsFile(text string) bool {
	_, err := os.Stat(text)
	return err == nil
}

func IsImage(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".png" || ext == ".jpg" || ext == ".jpeg"
}

func IsTextFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".txt"
}

func ConvertToRGBAFromPayload(payload *Payload) (*image.RGBA, error) {
	// Ensure the payload contains an image format
	fmt.Println(payload.Type)
	validImageFormats := map[string]bool{
			"image":  true,
			"png":    true,
			"jpeg":   true,
	}

	if !validImageFormats[payload.Type] {
			return nil, fmt.Errorf("payload type %s is not a supported image format", payload.Type)
	}

	img, _, err := image.Decode(bytes.NewReader(payload.Data))
	if err != nil {
			return nil, fmt.Errorf("failed to decode %s image: %v", payload.Type, err)
	}

	bounds := img.Bounds()
	rgbaImg := image.NewRGBA(bounds)

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
					rgbaImg.Set(x, y, img.At(x, y))
			}
	}

	return rgbaImg, nil
}


func SaveImage(path string, img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	outFile, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	multiWriter := io.MultiWriter(outFile, &buf)
	if err := png.Encode(multiWriter, img); err != nil {
		return nil, fmt.Errorf("error encoding output image: %v", err)
	}
	return buf.Bytes(), nil
}


// ComputeChecksum calculates the SHA-256 checksum of any binary data from a byte slice.
func ComputeChecksum(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}



// HasSufficientCapacity returns true if the image has enough capacity
// to embed the given payload. The capacity is defined as the number of bits
// available (3 bits per pixel) and the payload requires 32 bits (header) plus
// 8 bits per payload byte.
func HasSufficientCapacity(img *image.RGBA, payload *[]byte) bool {
	bounds := img.Bounds()
	// Calculate capacity: 3 bits per pixel (R, G, B channels).
	capacity := bounds.Dx() * bounds.Dy() * 3

	// Calculate required bits: 32 bits for the header (payload length) plus
	// 8 bits per byte of payload data.
	requiredBits := 32 + len(*payload)*8 // Dereference payload pointer correctly

	return capacity >= requiredBits
}
