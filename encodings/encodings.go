// Encodings are a group of wrapper methods for converting byte buffers
// to and from hex and base64 encodings,
package encodings

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBytes(s string) []byte {
	bytes, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return bytes
}

func Base64ToBytes(s string) []byte {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}

func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func BytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
