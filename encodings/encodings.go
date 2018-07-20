// Package encodings contains a group of wrapper methods for converting byte buffers
// to and from hex and base64 encodings,
package encodings

import (
	"encoding/base64"
	"encoding/hex"
)

// HexToBytes takes a string of hexadecimal characters and converts it to a slice of bytes
func HexToBytes(s string) []byte {
	bytes, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return bytes
}

// Base64ToBytes takes a string of base64 characters and converts it to a slice of bytes
func Base64ToBytes(s string) []byte {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}

// BytesToHex converts a slice of bytes to a string of hexadecimal characters
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// BytesToBase64 converts a slice of bytes to a string of base64 characters
func BytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
