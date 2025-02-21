package lsb

import (
	"errors"
	"image"
)

// setLSB sets the least significant bit of a value to the provided bit (0 or 1).
func setLSB(val uint8, bit uint8) uint8 {
	return (val & 0xFE) | (bit & 1)
}

// EncodeLSB encodes the provided message into the given RGBA image using LSB steganography.
// The first 32 bits (big-endian) encode the message length (in bytes).
// The message is then encoded in the R, G, and B channels (one bit per channel).
func EncodeLSB(img *image.RGBA, message string) error {
	messageBytes := []byte(message)
	messageLen := uint32(len(messageBytes))
	totalBits := 32 + len(messageBytes)*8 // 32 bits for header + 8 bits per message byte

	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	capacity := width * height * 3 // 3 bits per pixel (R, G, B)
	if totalBits > capacity {
		return errors.New("image is too small to hold the message")
	}

	// Create a slice to hold all bits to encode.
	bits := make([]uint8, totalBits)

	// Encode the message length (32 bits, big-endian).
	for i := 0; i < 32; i++ {
		shift := 31 - i
		bits[i] = uint8((messageLen >> shift) & 1)
	}

	// Encode the message bytes (8 bits per byte).
	for i, b := range messageBytes {
		for j := 0; j < 8; j++ {
			shift := 7 - j
			bits[32+i*8+j] = (b >> shift) & 1
		}
	}

	bitIndex := 0
	// Iterate over each pixel, modifying the R, G, and B channels.
	for y := bounds.Min.Y; y < bounds.Max.Y && bitIndex < totalBits; y++ {
		for x := bounds.Min.X; x < bounds.Max.X && bitIndex < totalBits; x++ {
			origColor := img.RGBAAt(x, y)
			if bitIndex < totalBits {
				origColor.R = setLSB(origColor.R, bits[bitIndex])
				bitIndex++
			}
			if bitIndex < totalBits {
				origColor.G = setLSB(origColor.G, bits[bitIndex])
				bitIndex++
			}
			if bitIndex < totalBits {
				origColor.B = setLSB(origColor.B, bits[bitIndex])
				bitIndex++
			}
			// Alpha channel remains unchanged.
			img.SetRGBA(x, y, origColor)
		}
	}

	return nil
}

