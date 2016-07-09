package cryptopals

import (
	"crypto/aes"
	"fmt"
	"strings"
	"testing"

	"github.com/ianferguson/cryptopals/encodings"
	"github.com/ianferguson/cryptopals/pkcs7"
)

func TestChallenge9(test *testing.T) {
	padded := pkcs7.Pad([]byte("YELLOW SUBMARINE"), 20)
	if len(padded) != 20 {
		test.Errorf("returned slice should've had a length of 20, but was %v", len(padded))
	}

	expected := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(padded) != expected {
		test.Errorf("padding returned %q instead of %q", string(padded), expected)
	}
}

// I'm back and I'm ringin' the bell
func TestChallenge10(test *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	ciphertext := encodings.Base64ToBytes(getURL("https://cryptopals.com/static/challenge-data/10.txt"))
	decrypted, err := decryptCBC(ciphertext, key)
	if err != nil {
		panic(err)
	}

	if !strings.Contains(string(decrypted), "bell") {
		test.Errorf("Expected %s to contain the phrase I'm back and I'm ringin' the bell", string(decrypted))
	}
}

func decryptCBC(ciphertext []byte, key []byte) (plaintext []byte, err error) {
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
		fmt.Printf("%s", xor(pBuf, chain))
		chain = ciphertext[:bs]
		ciphertext = ciphertext[bs:]
		p = p[bs:]
	}
	return plaintext, nil
}

// TODO before starting Challenge 11, test that encrypt works as well as decrypt
func encryptCBC(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := aes.BlockSize()
	ciphertext = make([]byte, len(plaintext))
	chain := make([]byte, bs)
	c := ciphertext
	for len(plaintext) > 0 {
		// TODO add padding like pkcs7.Pad(plaintext[:bs}, bs)])
		aes.Encrypt(c, xor(plaintext[:bs], chain))
		plaintext = plaintext[bs:]
		chain = c[:bs]
		c = c[bs:]
	}

	return ciphertext, nil
}

func TestChallenge11(test *testing.T) {
	test.Errorf("Challenge 11 not yet implemented")
}
