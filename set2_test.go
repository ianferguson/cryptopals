package cryptopals

import (
	"testing"

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
