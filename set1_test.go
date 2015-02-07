// http://cryptopals.com/sets/1/
package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

// Challenge 1 converts a provided hex string to binary and then from binary to base64, verifying its result
// http://cryptopals.com/sets/1/challenges/1/
func TestSet1Challenge1(test *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	output := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	bytes := hexToBytes(input)
	result := bytesToBase64(bytes)

	if result != output {
		test.Errorf("base64 encoded string was %v but %v was expected", result, input)
	}

}

// Challenge 2 takes tow inputs and xor's them together
// http://cryptopals.com/sets/1/challenges/2/
func TestSet1Challenge2(test *testing.T) {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"
	b1 := hexToBytes(input1)
	b2 := hexToBytes(input2)
	result := bytesToHex(xor(b1, b2))
	if result != expected {
		test.Errorf("expected %v but got %v", expected, result)
	}
}

func hexToBytes(s string) []byte {
	bytes, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return bytes
}

func base64ToBytes(s string) []byte {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}

func bytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func bytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func xor(a []byte, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("array a and b had differing lengths (%v and %v respectievely", len(a), len(b)))
	}

	l := len(a)
	out := make([]byte, l)
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}
