// Package pkcs7 implements PKCS#7 padding for inputs
package pkcs7

// Pad returns a slice of the provided slice appended with N bytes
// all having the value N, where N is the number of bytes needed to pad the input
// to be the provided keyLen length
func Pad(b []byte, keyLen int) []byte {
	padLen := keyLen - (len(b) % keyLen)
	pad := make([]byte, padLen, padLen)
	for i := range pad {
		pad[i] = byte(padLen)
	}
	return append(b, pad...)
}
