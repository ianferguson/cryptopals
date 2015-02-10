// Package vigenere is a set of tools for analyzing and cracking cipher text that
// has been encyrpted using simple 1 and multibyte repeating xor sequences (i.e. a vigenere cipher)
package vigenere

import (
	"fmt"
	"io/ioutil"
	"math"

	"github.com/ianferguson/cryptopals/hamming"
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

func (s *Solution) String() string {
	return fmt.Sprintf("score: %v,\ntext: %q,\nkey: %q", s.Score, s.Text, s.Key)
}

// Crack Simple will attempt to find the best 1 byte key that a provided ciphertext
// has been xor'd with and returns a Solution detailing that result
func CrackSimple(bytes []byte) *Solution {
	best := &Solution{math.MaxFloat64, "", ' '}
	for key := 0; key < 256; key++ {
		xord := make([]byte, len(bytes))
		for i := range bytes {
			xord[i] = bytes[i] ^ byte(key)
		}

		score := score(xord)
		if score < best.Score {
			best = &Solution{score, string(xord), rune(key)}
		}
	}
	return best
}

// Crack takes a given ciphetext byte array (c) known to be encrypted with a vigenere cipher
// using a multibyte key and find the key length, ky and decrypted plain text
func Crack(c []byte) []byte {
	kl := keyLength(c)
	stripes := make([][]byte, kl)
	for i := range stripes {
		stripes[i] = []byte{}
	}
	for i := range c {
		stripes[i%kl] = append(stripes[i%kl], c[i])
	}
	key := make([]byte, kl)
	for i := range stripes {
		s := CrackSimple(stripes[i])
		key[i] = byte(s.Key)
	}
	return Encrypt(c, key)
}

// TODO, make this actually readable....
func keyLength(c []byte) int {
	bestLength, bestDist := 0, math.MaxFloat64
	// test all key lengths from 2 to 48, looking for one with the lowest edit distance
	// between blocks of the key length size
	for kl := 2; kl < 48; kl++ {
		// compare the 1st to the 2nd block, 2nd to 3rd and so on, and then average the total edit distance
		// by the number of comparisons made
		aggregateDist := 0
		comparisons := 0
		for i := 0; (i+2)*kl < len(c); i++ {
			first := c[i*kl : (i+1)*kl]
			second := c[(i+1)*kl : (i+2)*kl]
			aggregateDist += hamming.Distance(first, second)
			comparisons++
		}
		// first average to the avg dist of a key size block
		dist := float64(aggregateDist) / float64(comparisons)
		// then average by the keysize to get get an average edit distance per byte
		normalizedDist := dist / float64(kl)
		if normalizedDist < bestDist {
			bestDist = normalizedDist
			bestLength = kl
		}
	}
	return bestLength
}

// knowFreq contains how frequently each byte appears in some large repository of english
// language text, the current values were generated from http://www.anc.org/data/masc/corpus/
var knownFreq = func() []float64 {
	// TODO either hardcode the []float64 values in to here, or embed the text string
	// into a source file so that it gets statically bundled as needed
	bytes, err := ioutil.ReadFile("vigenere/masc-500k-combined.txt")
	if err != nil {
		panic(err)
	}
	return calcFreq(bytes)
}()

// score a given string by calculating the frequency of each
// ascii character within the string and comparing to a known benchmark source of char freqencies
func score(bytes []byte) float64 {
	freq := calcFreq(bytes)
	score := 0.0
	for i := range knownFreq {
		score += math.Abs(freq[i] - knownFreq[i])
	}
	return score / float64(len(bytes))
}

// calcFreq calculates the relative frequency of each byte in a given byte buffer
// returning an array with a length of 256 containing a floating point value that
// is the percentage that the byte represented by that index appears in the input
// (0 - 1, not 0 - 100)
func calcFreq(bytes []byte) []float64 {
	counts := make([]int, 256)
	for _, b := range bytes {
		counts[b]++
	}

	blen := float64(len(bytes))
	freq := make([]float64, 256)
	for i := range freq {
		freq[i] = float64(counts[i]) / blen
	}

	return freq
}
