# Stego Usage Guide

**StegnGo** is a small CLI tool that hides data (images or text) inside images. This is known as _steganography_. Optionally, data can be encrypted before embedding.

## Installation

Download or build the `stegngo` tool from the repository. Once available in your PATH, you can invoke it as follows:

---

## Basic Commands

- **encode**: Takes a container image (PNG or JPG) and a payload (file or text) and produces a new image with hidden data.
- **decode**: Takes an encoded image and extracts the hidden data.

## Options

- `--container=PATH`: Path to the container image (PNG/JPG) used to hide or reveal data.
- `--payload=PATH`: Path to the payload file (can also be raw text or typed directly if no file is specified for encoding).
- `--password=SECRET`: Password for AES encryption (defaults to 32-byte key derived via PBKDF2).
- `--no-encryption`: (Optional) Disables AES encryption.
- `--output=OUT_PATH`: Output path for the resulting stego image or extracted payload.
- `--filename=NAME`: (Optional) Name for the extracted file when decoding.
- `--checksum=HASH`: (Optional) SHA-256 checksum for validating the container image.

## Example: Encoding

```bash
# Encode a text file inside an image, with encryption enabled
stego encode \
  --container="cover.png" \
  --payload="some message or secret_message.txt" \
  --password="mysecretpass" \
  --output="" \
  --filename="myFile"
```
---
## Example: Decode
# Decode the hidden data from an image
```bash
stego decode \
  --container="encoded.png" \
  --password="mysecretpass" \
  --output="" \
  --filename="myFile"
```

## Alternative Run
  You can also run by:

  ```bash
  go run main.go decode [options]
  ```

Once decoding is complete, you will find the hidden content in either the root directory of the project or in thee specified output path.

---

Note: If --no-encryption is used, no AES encryption/decryption takes place, but data is still hidden via steganography

Note: I will be working in making a system usable tool