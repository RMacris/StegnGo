package lsb

import (
	"errors"
	"image"
)

// BitReader is a helper that reads bits sequentially from an RGBA image.
type BitReader struct {
	img     *image.RGBA      // source image
	current int              // number of bits read so far
	bounds  image.Rectangle  // image bounds
	max     int              // total bits available (width * height * 3)
}

// NextBit returns the next bit (LSB of a channel) from the image.
func (br *BitReader) NextBit() (uint8, error) {
	if br.current >= br.max {
		return 0, errors.New("no more bits available")
	}
	// Calculate pixel index and channel order.
	pixelIndex := br.current / 3
	channelIndex := br.current % 3
	width := br.bounds.Dx()
	// Determine pixel coordinates in row-major order.
	x := br.bounds.Min.X + (pixelIndex % width)
	y := br.bounds.Min.Y + (pixelIndex / width)
	pixel := br.img.RGBAAt(x, y)

	var bit uint8
	switch channelIndex {
	case 0:
		bit = pixel.R & 1
	case 1:
		bit = pixel.G & 1
	case 2:
		bit = pixel.B & 1
	}
	br.current++
	return bit, nil
}

// ReadBits reads n bits from the image and returns them as a slice.
func (br *BitReader) ReadBits(n int) ([]uint8, error) {
	bits := make([]uint8, n)
	for i := 0; i < n; i++ {
		b, err := br.NextBit()
		if err != nil {
			return nil, err
		}
		bits[i] = b
	}
	return bits, nil
}

// DecodeLSB decodes a hidden message from an RGBA image using LSB steganography.
// It expects the first 32 bits (big-endian) to encode the length of the message in bytes,
// followed by the message bits.
func DecodeLSB(img *image.RGBA) (string, error) {
	bounds := img.Bounds()
	capacity := bounds.Dx() * bounds.Dy() * 3

	br := &BitReader{
		img:     img,
		current: 0,
		bounds:  bounds,
		max:     capacity,
	}

	// Read 32 bits for the header that represents the message length.
	headerBits, err := br.ReadBits(32)
	if err != nil {
		return "", err
	}

	// Convert header bits (big-endian) to uint32.
	var messageLen uint32
	for i := 0; i < 32; i++ {
		messageLen = (messageLen << 1) | uint32(headerBits[i])
	}

	totalMsgBits := int(messageLen) * 8
	if br.current+totalMsgBits > capacity {
		return "", errors.New("image does not contain enough data for the message")
	}

	// Read the bits for the actual message.
	msgBits, err := br.ReadBits(totalMsgBits)
	if err != nil {
		return "", err
	}

	// Convert bits to bytes.
	messageBytes := make([]byte, messageLen)
	for i := 0; i < int(messageLen); i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b = b << 1
			b |= msgBits[i*8+j]
		}
		messageBytes[i] = b
	}

	return string(messageBytes), nil
}
