package lsb

import (
	"image"
	"image/color"
	"image/draw"
	"testing"
)

// createBlankImage creates a blank RGBA image of the given width and height.
func createBlankImage(width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Optionally fill the image with a solid color.
	draw.Draw(img, img.Bounds(), &image.Uniform{color.White}, image.Point{}, draw.Src)
	return img
}

// TestEncodeLSBAndDecodeLSB tests that encoding a message into an image
// and then decoding it retrieves the original message.
func TestEncodeLSBAndDecodeLSB(t *testing.T) {
	originalMessage := "Hello, World!"
	// Create an image with sufficient capacity.
	img := createBlankImage(10, 10) // Capacity = 10*10*3 = 300 bits

	// Encode the message.
	if err := EncodeLSB(img, originalMessage); err != nil {
		t.Fatalf("EncodeLSB failed: %v", err)
	}

	// Decode the message.
	decodedMessage, err := DecodeLSB(img)
	if err != nil {
		t.Fatalf("DecodeLSB failed: %v", err)
	}

	// Verify that the decoded message matches the original.
	if decodedMessage != originalMessage {
		t.Errorf("Decoded message %q does not match original %q", decodedMessage, originalMessage)
	}
}

// TestEncodeLSB_InsufficientCapacity verifies that EncodeLSB returns an error
// when the image does not have enough capacity to store the message.
func TestEncodeLSB_InsufficientCapacity(t *testing.T) {
	message := "This message is too long for a tiny image"
	// Create a very small image (1x1 pixel) with capacity = 3 bits.
	img := createBlankImage(1, 1)

	if err := EncodeLSB(img, message); err == nil {
		t.Error("Expected error due to insufficient capacity, but got nil")
	}
}
