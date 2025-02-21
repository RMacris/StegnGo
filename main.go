// main.go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	_ "image/jpeg" // so we can decode JPEGs
	_ "image/png"  // so we can decode PNGs
	"io"
	"log"
	"os"
	"path/filepath"

	lsb "stegngo/LSB"
	crypt "stegngo/encryption"
	utils "stegngo/utils"
)

// encodeCommand holds flags for the "encode" subcommand.
type encodeCommand struct {
	container    string
	payload      string
	password     string
	noEncryption bool
	output       string
}

// decodeCommand holds flags for the "decode" subcommand.
type decodeCommand struct {
	container    string
	password     string
	noEncryption bool
	output       string
	filename		 string
	checksum		 string
}

// main is the CLI entry point.
func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "encode":
		encodeCmd := parseEncodeFlags()
		if err := encodeCmd.run(); err != nil {
			fmt.Fprintln(os.Stderr, "Error in encode:", err)
			os.Exit(1)
		}
	case "decode":
		decodeCmd := parseDecodeFlags()
		if err := decodeCmd.run(); err != nil {
			fmt.Fprintln(os.Stderr, "Error in decode:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", cmd)
		printUsage()
		os.Exit(1)
	}
}

// printUsage prints basic usage information.
func printUsage() {
	fmt.Print(`Usage:
  stego encode [options]
	--container=PATH   Path to container image (PNG/JPG)
	--payload=PATH     Path to the payload file (text/image). 
					   If not given, you can type raw text via this flag or omit and enter via CLI prompt.
	--password=SECRET  Encryption password (32-byte key derived via PBKDF2).
	--no-encryption    Disable AES encryption even if password is provided.
	--output=OUT_PATH  Output path for the stego-image. Defaults to "encoded.png" if not specified.

  stego decode [options]
	--container=PATH   Path to container image (PNG/JPG) that holds the hidden message.
	--password=SECRET  Password used if data was encrypted.
	--no-encryption    Indicate that the data is not encrypted.
	--output=OUT_PATH  Output path for the extracted payload. Defaults to "extracted_payload.bin".`)
}


// parseEncodeFlags parses flags for the "encode" subcommand.
func parseEncodeFlags() *encodeCommand {
	enc := &encodeCommand{}
	fs := flag.NewFlagSet("encode", flag.ExitOnError)
	fs.StringVar(&enc.container, "container", "", "Path to container image")
	fs.StringVar(&enc.payload, "payload", "", "Path to payload file or raw text data")
	fs.StringVar(&enc.password, "password", "", "Password for AES encryption")
	fs.BoolVar(&enc.noEncryption, "no-encryption", false, "Disable encryption")
	fs.StringVar(&enc.output, "output", "encoded.png", "Output path for the encoded image")
	_ = fs.Parse(os.Args[2:])
	return enc
}

// parseDecodeFlags parses flags for the "decode" subcommand.
func parseDecodeFlags() *decodeCommand {
	dec := &decodeCommand{}
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	fs.StringVar(&dec.container, "container", "", "Path to container image containing hidden data")
	fs.StringVar(&dec.password, "password", "", "Password for AES decryption")
	fs.BoolVar(&dec.noEncryption, "no-encryption", false, "Disable encryption/decryption")
	fs.StringVar(&dec.output, "output", "", "Output path for the extracted payload")
	fs.StringVar(&dec.filename, "filename", "output", "Output filename for the extracted payload")
	fs.StringVar(&dec.checksum, "checksum", "", "SHA-256 checksum of the container image")
	_ = fs.Parse(os.Args[2:])
	return dec
}

func (enc *encodeCommand) run() error {
	// Ensure a container path is provided.
	if enc.container == "" {
		return errors.New("missing --container for encode")
	}

	// Verify the container file is indeed an image.
	if !utils.IsImage(enc.container) {
		return errors.New("container image must be a PNG or JPEG")
	}

	// Load the container image.
	containerImg, _, err := utils.LoadFile(enc.container)
	if err != nil {
		return fmt.Errorf("failed to load container image: %v", err)
	}

	payloadData := &utils.Payload{}

	if utils.IsFile(enc.payload) {
			// It's a file path, so load from disk.
			loadedPayload, _, err := utils.LoadFile(enc.payload)
			if err != nil {
					return fmt.Errorf("failed to load payload data: %v", err)
			}
			payloadData = loadedPayload
	} else {
			// It's not a file path, so treat enc.payload as raw text.
			payloadData = &utils.Payload{
					Type: "txt",
					Data: []byte(enc.payload),
			}
	}

	// is empty byte array 
	if(payloadData == nil || payloadData.Data == nil){
		return errors.New("payload data is empty")
	}

	if err != nil {
		return fmt.Errorf("failed to resolve payload: %v", err)
	}

	// If a password was provided, load it from a file (if applicable).
	if enc.password != "" && utils.IsTextFile(enc.password) {
		passwordFile, _, err := utils.LoadFile(enc.password)
		if err != nil {
			return fmt.Errorf("failed to resolve password: %v", err)
		}
		enc.password = string(passwordFile.Data) // Replace `enc.password` with file content
	}

	// Encrypt if necessary (or use a random key if no password is supplied).
	var cipherTextStr, saltHex, nonceHex, usedKeyStr string

	serializedPayload, err := utils.SerializePayload(*payloadData)
	if !enc.noEncryption {
		if enc.password != "" {
			if err != nil {
				return fmt.Errorf("failed to serialize payload: %v", err)
			}

			cipherTextStr, saltHex, nonceHex, err = crypt.EncryptAESGCM([]byte(enc.password), serializedPayload)
			if err != nil {
				return fmt.Errorf("failed to encrypt payload: %v", err)
			}
			usedKeyStr = fmt.Sprintf("Salt: %s, Nonce: %s", saltHex, nonceHex)
		} else {
			// Case 2: No password → Generate a random key
			randomKey := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, randomKey); err != nil {
				return fmt.Errorf("failed to generate random encryption key: %v", err)
			}
			cipherTextStr, saltHex, nonceHex, err = crypt.EncryptAESGCM(randomKey, serializedPayload)
			if err != nil {
				return fmt.Errorf("failed to encrypt payload: %v", err)
			}
			usedKeyStr = fmt.Sprintf("Generated Key (hex): %s, Salt: %s, Nonce: %s", hex.EncodeToString(randomKey), saltHex, nonceHex)
		}
	} else {
		// No encryption: Use raw payload data
		cipherTextStr = string(serializedPayload)
	}

	// Convert container to RGBA for steganographic encoding.
	rgbaContainer, err := utils.ConvertToRGBAFromPayload(containerImg)
	if err != nil {
		return fmt.Errorf("failed to convert container to RGBA: %v", err)
	}

	// Ensure the container image has enough capacity to embed our data.
	cipherTextBytes := []byte(cipherTextStr)
	if !utils.HasSufficientCapacity(rgbaContainer, &cipherTextBytes) {
		return errors.New("image does not have enough capacity to store payload")
	}

	// Encode the data into the container image using LSB.
	dataToEncode := cipherTextStr
	if !enc.noEncryption {
		dataToEncode = utils.AddCypherMetadata(saltHex, nonceHex, cipherTextStr)
	}

	if err := lsb.EncodeLSB(rgbaContainer, dataToEncode); err != nil {
		return fmt.Errorf("failed to encode payload with LSB: %v", err)
	}

	// Save the stego image to the specified output.
	outPath := enc.output
	saved, err := utils.SaveImage(outPath, rgbaContainer)

	if  err != nil {
		return fmt.Errorf("failed to save stego image: %v", err)
	}

	// Compute and display the checksum of the final image.
	if err != nil {
		return fmt.Errorf("failed to convert image to bytes: %v", err)
	}

	checksum, err := utils.ComputeChecksum(saved)
	if err != nil {
		return fmt.Errorf("failed to compute checksum of output: %v", err)
	}

	fmt.Println("Stego image created at:", outPath)
	fmt.Println("Used Key Information:", usedKeyStr)

	if enc.password == "" && !enc.noEncryption {
		fmt.Println("No encryption password used")
		fmt.Println("Generated Key for Decryption:", usedKeyStr)
	}

	fmt.Println("SHA-256 Checksum:", checksum)
	return nil
}


// run executes the decode logic. The user must always provide a password.
func (dec *decodeCommand) run() error {
	// Check container
	if dec.container == "" {
		return errors.New("missing --container for decode")
	}
	if !utils.IsImage(dec.container) {
		return errors.New("container image must be a PNG or JPEG")
	}	

	// Load the container.
	containerImg, rawData, err := utils.LoadFile(dec.container)
	if err != nil {
		return fmt.Errorf("failed to load container: %v", err)
	}

	//checksum verification

	if dec.checksum != "" {
		// Compute the checksum of the container image.
		checksum, err := utils.ComputeChecksum(rawData)
		fmt.Println(checksum)
		if err != nil {
			return fmt.Errorf("failed to compute checksum of container: %v", err)
		}
		// Compare the computed checksum with the provided checksum.
		if checksum != dec.checksum {
			return errors.New("container image checksum does not match provided checksum")
		}
	}
	
	// Convert to RGBA so we can decode the LSB.
	rgbaContainer, err := utils.ConvertToRGBAFromPayload(containerImg)
	if err != nil {
		return fmt.Errorf("failed to convert container to RGBA: %v", err)
	}

	// Decode the stego data.
	decodedString, err := lsb.DecodeLSB(rgbaContainer)
	if err != nil {
		return fmt.Errorf("failed to decode stego data: %v", err)
	}

  var salty, nonce, cipher string
  salty, nonce, cipher = utils.ExtractCypherMetadata(decodedString)

	// A password is always required — remove no-encryption option.
	if dec.password != "" && utils.IsTextFile(dec.password) {
		passwordFile, _, err := utils.LoadFile(dec.password)
		if err != nil {
			return fmt.Errorf("failed to resolve password: %v", err)
		}
		dec.password = string(passwordFile.Data)
	}

	if dec.password == "" {
		return fmt.Errorf("a password is required for decoding")
	}

	plaintext, err := crypt.DecryptAESGCM([]byte(dec.password), cipher, salty, nonce)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	deserializedPayload, err := utils.DeserializePayload(plaintext)
	if err != nil {
		return fmt.Errorf("failed to deserialize payload: %v", err)
	}
	
	dec.filename = utils.SanitizeFileName(dec.filename)
	fmt.Println(dec.filename)
	if !utils.IsValidDirectory(dec.output) {
		return fmt.Errorf("output directory is not valid")
	}
	dec.output = filepath.Join(dec.output, fmt.Sprintf("%s.%s", dec.filename, deserializedPayload.Type))
	dec.output = filepath.Clean(dec.output)	
	
	outputFilename := filepath.Clean(dec.output)


	// Write the output to the specified file.
	if err := os.WriteFile(outputFilename, deserializedPayload.Data, 0666); err != nil {
		log.Fatalf("Failed to write decoded data: %v", err)
	}

	fmt.Println("Decoded data saved to:", dec.output)
	return nil
}