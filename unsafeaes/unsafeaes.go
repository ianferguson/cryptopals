// Package unsafeaes contains helper functions used in solving the Matasano
// Cryptopals challenges and is in no way an actual usable set of cryptographic tools
package unsafeaes

import (
	"bytes"
	"crypto/aes"

	"github.com/ianferguson/cryptopals/pkcs7"
)

func DecryptCBC(ciphertext []byte, key []byte) (plaintext []byte, err error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := aes.BlockSize()
	plaintext = make([]byte, len(ciphertext))
	chain := make([]byte, bs)
	p := plaintext
	pBuf := make([]byte, bs)
	for len(ciphertext) > 0 {
		aes.Decrypt(pBuf, ciphertext)
		copy(p, xor(pBuf, chain))
		// only useful for debugging, I'd normally not leave in commented
		// out code, but the combination of learning the language and learning
		// the cryptographic portions at the same time, and no one else using this code,
		// makes leaving in hints/pointers to myself like this feel fine
		// fmt.Printf("%s", xor(pBuf, chain))
		chain = ciphertext[:bs]
		ciphertext = ciphertext[bs:]
		p = p[bs:]
	}
	return plaintext, nil
}

func EncryptCBC(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := aes.BlockSize()
	plaintext = pkcs7.Pad(plaintext, bs)
	ciphertext = make([]byte, len(plaintext))
	chain := make([]byte, bs)
	c := ciphertext
	for len(plaintext) > 0 {
		aes.Encrypt(c, xor(plaintext[:bs], chain))
		plaintext = plaintext[bs:]
		chain = c[:bs]
		c = c[bs:]
	}

	return ciphertext, nil
}

func EncryptEBC(plaintext, key []byte) (ciphertext []byte, err error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := aes.BlockSize()
	plaintext = pkcs7.Pad(plaintext, bs)
	ciphertext = make([]byte, len(plaintext))
	c := ciphertext
	for len(plaintext) > 0 {
		aes.Encrypt(c, plaintext[:bs])
		plaintext = plaintext[bs:]
		c = c[bs:]
	}

	return ciphertext, nil
}

// look for repeating blocks in the output text -- since we fed a series of 0's to it, ECB will result
// in at least 2 duplicate blocks existing, while CBC will not.
// this is obviously wildly O(n^2) inefficient, but will work for now
func DetectMode(plaintext, ciphertext []byte) string {
	keySize := 16
	blocks := (len(ciphertext) / keySize) + 1
	seen := make([][]byte, 0, blocks)
	for i := 0; i < len(ciphertext); i += keySize {
		block := ciphertext[i : i+keySize]
		for _, seenBlock := range seen {
			if bytes.Equal(block, seenBlock) {
				return "EBC"
			}
		}
		seen = append(seen, block)
	}
	return "CBC"
}
