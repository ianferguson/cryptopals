// http://cryptopals.com/sets/1/
package cryptopals

import (
	"github.com/ianferguson/cryptopals/encodings"
	"github.com/ianferguson/cryptopals/xorcipher"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

// Challenge 1 converts a provided hex string to binary and then from binary to base64, verifying its result
// http://cryptopals.com/sets/1/challenges/1/
func TestSet1Challenge1(test *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	output := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	bytes := encodings.HexToBytes(input)
	result := encodings.BytesToBase64(bytes)

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
	b1 := encodings.HexToBytes(input1)
	b2 := encodings.HexToBytes(input2)
	result := encodings.BytesToHex(xor(b1, b2))
	if result != expected {
		test.Errorf("expected %v but got %v", expected, result)
	}
}

// Challenge 3 is to crack a hex string that has been xor'd with a 1 byte key
// http://cryptopals.com/sets/1/challenges/3/
func TestSet1Challenge3(test *testing.T) {
	hexInput := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	output := xorcipher.CrackSimple(encodings.HexToBytes(hexInput))
	expected := "Cooking MC's like a pound of bacon"
	if output.Text != expected {
		test.Errorf("expected the input to decode to %v but got %v instead", expected, output.Text)
	}

	if output.Key != 'X' {
		test.Errorf("expected the key to be guessed as 'A' but was %q", output.Key)
	}
}

// Challenge 4 is to locate the 1 string within 60 hex snippets that is a
// an english string xor'd with a 1 byte key
// http://cryptopals.com/sets/1/challenges/4/
func TestSet1Challenge4(test *testing.T) {
	response, e := http.Get("http://cryptopals.com/static/challenge-data/4.txt")
	if e != nil {
		panic(e)
	}
	defer response.Body.Close()
	codes, e := ioutil.ReadAll(response.Body)
	if e != nil {
		panic(e)
	}

	expected := "Now that the party is jumping\n"
	var found string
	for _, code := range strings.Split(string(codes), "\n") {
		s := xorcipher.CrackSimple(encodings.HexToBytes(code))
		if s.Score > 4.6 {
			found = s.Text
		}
	}

	if found != expected {
		test.Errorf("expected clear text to be found with message %v but found %v", expected, found)
	}
}
