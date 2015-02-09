// http://cryptopals.com/sets/1/
package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"unicode"
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

func TestSet1Challenge3(test *testing.T) {
	hexInput := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	output := decodeSingleCharXor(hexToBytes(hexInput))
	expected := "Cooking MC's like a pound of bacon"
	if output.text != expected {
		test.Errorf("expected the input to decode to %v but got %v instead", expected, output.text)
	}

	if output.key != 'X' {
		test.Errorf("expected the key to be guessed as 'A' but was %q", output.key)
	}
}

type solution struct {
	score float64
	text  string
	key   rune
}

func decodeSingleCharXor(bytes []byte) *solution {

	bestSolution := new(solution)
	for key := 0; key < 256; key++ {
		xord := make([]byte, len(bytes))
		for i := range bytes {
			xord[i] = bytes[i] ^ byte(key)
		}

		decrypted := string(xord)
		score := score(decrypted)
		if score > bestSolution.score {
			bestSolution = &solution{score, decrypted, rune(key)}
		}
		fmt.Printf("%v: %q\n", score, decrypted)
	}
	return bestSolution
}

// frequency returns a value indicating a given rune's frequency
// in the english language, values are only guarunteed to be useful in
// comparison to each other and not as any absolute metric
var runeFreq = map[rune]float64{
	' ': 24.50,
	'E': 12.51,
	'T': 9.25,
	'A': 8.04,
	'O': 7.60,
	'I': 7.26,
	'N': 7.09,
	'S': 6.54,
	'R': 6.12,
	'H': 5.49,
	'L': 4.14,
	'D': 3.99,
	'C': 3.06,
	'U': 2.71,
	'M': 2.53,
	'F': 2.30,
	'P': 2.00,
	'G': 1.96,
	'W': 1.92,
	'Y': 1.73,
	'B': 1.54,
	'V': 0.99,
	'K': 0.67,
	'X': 0.19,
	'J': 0.16,
	'Q': 0.11,
	'Z': 0.09,
}

func score(s string) float64 {
	score := 0.0
	for _, r := range s {
		// penalize heavily for non printable characters, since they are pretty good indicators
		// that the bytes being examined are not english/characters
		if !unicode.IsPrint(r) {
			score -= 120
		} else {
			score += runeFreq[unicode.ToUpper(r)]
		}
	}
	return score / float64(len(s))
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
