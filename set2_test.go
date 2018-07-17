package cryptopals

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"strings"
	"testing"

	"github.com/ianferguson/cryptopals/encodings"
	"github.com/ianferguson/cryptopals/pkcs7"
	"github.com/ianferguson/cryptopals/unsafeaes"
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
	decrypted, err := unsafeaes.DecryptCBC(ciphertext, key)
	if err != nil {
		panic(err)
	}

	if !strings.Contains(string(decrypted), "bell") {
		test.Errorf("Expected %s to contain the phrase I'm back and I'm ringin' the bell", string(decrypted))
	}
}

/*
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
*/
func TestChallenge11Cbc(test *testing.T) {
	plaintext := make([]byte, 256)
	ciphertext, err := encryptionOracle(plaintext, cbc)
	if err != nil {
		panic(err)
	}

	mode := unsafeaes.DetectMode(plaintext, ciphertext)
	if mode != "CBC" {
		test.Errorf("expected AES mode CBC to be detected but instead detected %s", mode)
	}
}

func TestChallenge11Ebc(test *testing.T) {
	plaintext := make([]byte, 256)
	ciphertext, err := encryptionOracle(plaintext, ebc)
	if err != nil {
		panic(err)
	}

	mode := unsafeaes.DetectMode(plaintext, ciphertext)
	if mode != "EBC" {
		test.Errorf("expected AES mode EBC to be detected but instead detected %s", mode)
	}
}

type aesmode int

const (
	ebc aesmode = iota
	cbc
	random
)

// encryptionOracle that lets you optionally specify the aes mode being used,
// to facilitate verification/testing of the code decyphering the output of the oracle
func encryptionOracle(input []byte, mode aesmode) (ciphertext []byte, err error) {
	frontPad := randomBytes(5, 10)
	backPad := randomBytes(5, 10)
	plaintext := append(append(frontPad, input...), backPad...)
	key := key(16)
	return encryptUsing(mode)(plaintext, key)
}

func encryptUsing(mode aesmode) func([]byte, []byte) ([]byte, error) {
	switch mode {
	case cbc:
		return unsafeaes.EncryptCBC
	case ebc:
		return unsafeaes.EncryptEBC
	case random:
		i, err := rand.Int(rand.Reader, big.NewInt(int64(random)))
		if err != nil {
			panic(err)
		}
		var randomMode aesmode
		randomMode = aesmode(int(i.Int64()))
		return encryptUsing(randomMode)
	}
	panic(fmt.Sprintf("mode %d is not known", mode))
}

// XXX not for final commit, sketch space for Set 2, Challenge 11
func key(size int) []byte {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		panic("unreachable")
	}
	return key
}

func randomBytes(min, max int) []byte {
	random, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		panic(err)
	}
	return make([]byte, random.Add(random, big.NewInt(int64(min))).Int64())
}
