package lsb

import (
	"image"
	"testing"
)

// TestDecodeLSB_ValidMessage creates an image with an embedded message "A" and verifies that DecodeLSB returns the correct string.
func TestDecodeLSB_ValidMessage(t *testing.T) {
	// Define image dimensions.
	width, height := 5, 3
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Total available bits = width * height * 3 (here 5*3*3 = 45 bits).

	// Prepare the header: 32 bits representing the message length.
	// For a single-character message ("A"), the length is 1.
	// In big-endian, that is 31 zeros followed by a 1.
	headerBits := make([]uint8, 32)
	headerBits[31] = 1 // Only the least significant bit is 1.

	// Prepare the message bits for "A" (ASCII 65 = 01000001).
	messageBits := []uint8{0, 1, 0, 0, 0, 0, 0, 1}

	// Combine header and message bits.
	allBits := append(headerBits, messageBits...)

	// Embed the bits into the image's pixels.
	// The BitReader logic uses:
	//   pixelIndex = current / 3
	//   channelIndex = current % 3
	//   x = bounds.Min.X + (pixelIndex % width)
	//   y = bounds.Min.Y + (pixelIndex / width)
	for i, bit := range allBits {
		pixelIndex := i / 3
		channelIndex := i % 3
		x := img.Rect.Min.X + (pixelIndex % width)
		y := img.Rect.Min.Y + (pixelIndex / width)

		pixel := img.RGBAAt(x, y)
		// Set the LSB of the selected channel to the bit value.
		switch channelIndex {
		case 0:
			pixel.R = (pixel.R & 0xFE) | bit
		case 1:
			pixel.G = (pixel.G & 0xFE) | bit
		case 2:
			pixel.B = (pixel.B & 0xFE) | bit
		}
		img.SetRGBA(x, y, pixel)
	}

	// Decode the hidden message.
	decodedMessage, err := DecodeLSB(img)
	if err != nil {
		t.Fatalf("DecodeLSB failed: %v", err)
	}

	expected := "A"
	if decodedMessage != expected {
		t.Errorf("Expected message %q, got %q", expected, decodedMessage)
	}
}

// TestDecodeLSB_InsufficientCapacity creates an image that is too small to hold even the 32-bit header.
func TestDecodeLSB_InsufficientCapacity(t *testing.T) {
	// Create a 1x1 image: capacity = 1*1*3 = 3 bits, which is less than the required 32 bits.
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	_, err := DecodeLSB(img)
	if err == nil {
		t.Error("Expected error due to insufficient capacity, but got none")
	}
}
