// xorcipher is a set of tools for analyzing and cracking cipher text that
// has been encyrpted using simple 1 and multibyte repeating xor sequences
package xorcipher

import (
	"unicode"
)

// Encrypt takes a plaintext (p) of bytes and a key (k) of a variable number of bytes
// and xors the plaintext with the provided key, with the key being repeated as
// necessary if the plaintext is longer than the key
func Encrypt(p []byte, k []byte) []byte {
	c := make([]byte, len(p))
	for i := range p {
		c[i] = p[i] ^ k[i%len(k)]
	}
	return c
}

type Solution struct {
	Score float64
	Text  string
	Key   rune
}

// Crack Simple will attempt to find the best 1 byte key that a provided ciphertext
// has been xor'd with and returns a Solution detailing that result
func CrackSimple(bytes []byte) *Solution {
	best := new(Solution)
	for key := 0; key < 256; key++ {
		xord := make([]byte, len(bytes))
		for i := range bytes {
			xord[i] = bytes[i] ^ byte(key)
		}

		decrypted := string(xord)
		score := score(decrypted)
		if score > best.Score {
			best = &Solution{score, decrypted, rune(key)}
		}
	}
	return best
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
		// penalize heavily for non-ascii characters, since they are pretty good indicators
		// that the bytes being examined are not english/characters
		if r > 255 {
			score -= 240
		} else {
			score += runeFreq[unicode.ToUpper(r)]
		}
	}
	return score / float64(len(s))
}
