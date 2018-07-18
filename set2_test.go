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

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and
encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes
after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each
time for CBC).
Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at
a block box that might be encrypting ECB or CBC, tells you which one is happening.
*/
func TestChallenge11Cbc(test *testing.T) {
	mode, err := unsafeaes.DetectMode(cbcOracle{})
	if err != nil {
		panic(err)
	}

	if mode != "CBC" {
		test.Errorf("expected AES mode CBC to be detected but instead detected %s", mode)
	}
}

type cbcOracle struct{}

func (oracle cbcOracle) Encrypt(input []byte) (ciphertext []byte, err error) {
	frontPad := randomBytes(5, 10)
	backPad := randomBytes(5, 10)
	plaintext := append(append(frontPad, input...), backPad...)
	key := key(16)
	return unsafeaes.EncryptCBC(plaintext, key)
}

func TestChallenge11Ecb(test *testing.T) {
	mode, err := unsafeaes.DetectMode(ecbOracle{})
	if err != nil {
		panic(err)
	}

	if mode != "ECB" {
		test.Errorf("expected AES mode ECB to be detected but instead detected %s", mode)
	}
}

type ecbOracle struct{}

func (oracle ecbOracle) Encrypt(input []byte) (ciphertext []byte, err error) {
	frontPad := randomBytes(5, 10)
	backPad := randomBytes(5, 10)
	plaintext := append(append(frontPad, input...), backPad...)
	key := key(16)
	return unsafeaes.EncryptECB(plaintext, key)
}

// decode encrypted text returned by an oracle
// challenge guidlines/steps are interpolated as comments
func TestChallenge12(test *testing.T) {
	// Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
	// then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
	oracle := challenge12Oracle{key(16)}
	blockSize, err := unsafeaes.DetectBlockSize(oracle)
	if err != nil {
		panic(err)
	}
	if blockSize != 16 {
		test.Errorf("Expected block size to be 16 but was %d", blockSize)
	}

	// Detect that the function is using ECB. You already know, but do this step anyways.
	mode, err := unsafeaes.DetectMode(oracle)
	if err != nil {
		panic(err)
	}
	if mode != "ECB" {
		test.Errorf("Expected to detect AES mode ECB, but instead detected %s", mode)
	}

	// Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is
	// 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
	shortBlock := make([]byte, blockSize-1)
	plaintextSize, err := findTextLength(oracle)
	if err != nil {
		panic(err)
	}
	test.Logf("Oracle's plaintext is %d bytes long", plaintextSize)

	// Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA",
	// "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
	lastbyte := make(map[string]byte)

	// XXX handle 255 without rolling over and missing the loop condition
	for b := 0; b < 256; b++ {
		fmt.Printf("Evaluating byte %x\n", b)
		ciphertext, err := oracle.Encrypt(append(shortBlock, byte(b)))
		if err != nil {
			panic(err)
		}
		firstBlock := ciphertext[:blockSize]
		fmt.Printf("Got back %x\n", firstBlock)
		lastbyte[encodings.BytesToHex(firstBlock)] = byte(b)
	}

	ciphertext, err := oracle.Encrypt(shortBlock)
	if err != nil {
		panic(err)
	}

	// Match the output of the one-byte-short input to one of the entries in your dictionary.
	// You've now discovered the first byte of unknown-string.
	firstBlock := ciphertext[:blockSize]
	b := lastbyte[encodings.BytesToHex(firstBlock)]
	test.Logf("found byte %x/%#U for %x", b, rune(b), firstBlock)

	// Repeat for the next byte.

	test.Error("not yet implemented")
}

func findTextLength(oracle unsafeaes.Oracle) (length int, err error) {
	maxPadSize := 1024
	for padSize := 0; padSize < maxPadSize; padSize++ {
		plaintext := make([]byte, padSize)
		ciphertext, err := oracle.Encrypt(plaintext)
		if err != nil {
			return -1, err
		}

		if length == 0 {
			length = len(ciphertext)
		}

		if len(ciphertext) > length {
			return len(ciphertext) - padSize, nil
		}
	}

	return -1, fmt.Errorf("Unable to detect size of hidden text used by oracle, tested up to %d bytes in padding", maxPadSize)
}

type challenge12Oracle struct {
	key []byte
}

func (this challenge12Oracle) Encrypt(input []byte) (ciphertext []byte, err error) {
	backPad := encodings.Base64ToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg")
	plaintext := append(input, backPad...)
	return unsafeaes.EncryptECB(plaintext, this.key)
}

// XXX below here is not for final commit, sketch space for Set 2, Challenge 11-12
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
