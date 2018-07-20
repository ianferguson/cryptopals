// Package unsafeaes contains helper functions used in solving the Matasano
// Cryptopals challenges and is in no way an actual usable set of cryptographic tools
package unsafeaes

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/ianferguson/cryptopals/pkcs7"
)

// Oracle will take an input plaintext, possibly prepend and/or append unknown text
// to the plaintext and then encrypt or otherwise prform an unknown cryptographic
// operation on the resulting input and return the result
type Oracle interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
}

// DecryptCBC decrypts a provided ciphertext encrypted with AES-CBC mode
// using the provided key.
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

// EncryptCBC encrypts the provided plaintext using AES in CBC mode using the provided key
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

// EncryptECB encrypts the provided plaintext using AES in EBC mode
func EncryptECB(plaintext, key []byte) (ciphertext []byte, err error) {
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

// DetectBlockSize auto detects the block size (up to 1024 bytes) of the ciphertext returned
// by an oracle
func DetectBlockSize(oracle Oracle) (blockSize int, err error) {
	maxTestSize := 1024
	var size int
	for i := 1; i <= maxTestSize; i++ {
		plaintext := make([]byte, i)
		ciphertext, err := oracle.Encrypt(plaintext)
		if err != nil {
			return -1, err
		}
		if size == 0 {
			size = len(ciphertext)
		}
		if len(ciphertext) > size {
			return len(ciphertext) - size, nil
		}

	}
	return -1, fmt.Errorf("Unable to detect blocksize used by oracle, tested up to %d bytes", maxTestSize)
}

// DetectMode looks for repeating blocks in the output text to try to determine if a provided encryption oracle
// is using EBC mode or not
//
// since we fed a series of 0's to it, ECB will result
// in at least 2 consecutive duplicate blocks existing, while CBC will not.
func DetectMode(oracle Oracle) (mode string, err error) {
	blockSize, err := DetectBlockSize(oracle)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, blockSize*3)
	ciphertext, err := oracle.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	previous := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	for len(ciphertext) > blockSize {
		next := ciphertext[:blockSize]
		if bytes.Equal(next, previous) {
			return "ECB", nil
		}
		ciphertext = ciphertext[blockSize:]
		previous = next
	}
	return "CBC", nil
}
