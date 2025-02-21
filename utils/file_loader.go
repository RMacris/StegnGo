package utils

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
)

// Payload represents a file's type and raw data.
type Payload struct {
	Type string // Stores the actual file extension (e.g., "png", "jpg", "txt")
	Data []byte
}

// Function signature for dynamic file loaders
type fileLoaderFunc func(data []byte, ext string) (*Payload, []byte, error)

// Image Loader: Decodes & re-encodes image data, but stores the correct file extension.
func imageLoader(data []byte, ext string) (*Payload, []byte, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode image: %v", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, nil, fmt.Errorf("failed to encode image as PNG: %v", err)
	}

	return &Payload{
		Type: strings.TrimPrefix(ext, "."), // Store "png", "jpg", etc.
		Data: buf.Bytes(),
	}, data, nil
}

// Text Loader: Simply stores text file data.
func textLoader(data []byte, ext string) (*Payload, []byte, error) {
	return &Payload{
		Type: strings.TrimPrefix(ext, "."), // Store "txt"
		Data: data,
	}, data, nil
}

// LoadFile: Reads a file and determines its type dynamically.
func LoadFile(filePath string) (*Payload, []byte, error) {
	ext := strings.ToLower(filepath.Ext(filePath)) // Get the file extension
	if ext == "" {
		return nil, nil, fmt.Errorf("file %s has no extension", filePath)
	}

	// Define allowed file types
	allowed := map[string]bool{
		".png":  true,
		".jpg":  true,
		".jpeg": true,
		".txt":  true,
	}
	if !allowed[ext] {
		return  nil, nil, fmt.Errorf("file extension %s not allowed", ext)
	}

	// Read the file into memory
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %v", err)
	}

	// Define loaders per file extension
	loaders := map[string]fileLoaderFunc{
		".png":  imageLoader,
		".jpg":  imageLoader,
		".jpeg": imageLoader,
		".txt":  textLoader,
	}

	// Select the appropriate loader
	loader, ok := loaders[ext]
	if !ok {
		return  nil, nil, fmt.Errorf("no loader defined for extension %s", ext)
	}

	// Load file using the selected loader, passing the extension
	return loader(fileData, ext)
}
