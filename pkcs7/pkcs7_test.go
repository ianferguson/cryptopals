package pkcs7

import (
	"testing"
)

func TestPad(test *testing.T) {
	padded := Pad([]byte("foo bar baz"), 8)
	if len(padded) != 16 {
		test.Errorf("returned slice should've had a length of 16, but was %v", len(padded))
	}

	expected := "foo bar baz\x05\x05\x05\x05\x05"
	if string(padded) != expected {
		test.Errorf("padding returned %q instead of %q", string(padded), expected)
	}
}
