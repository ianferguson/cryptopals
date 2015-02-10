// http://cryptopals.com/sets/1/
package cryptopals

import (
	"crypto/aes"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/ianferguson/cryptopals/encodings"
	"github.com/ianferguson/cryptopals/vigenere"
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
	output := vigenere.CrackSimple(encodings.HexToBytes(hexInput))
	expected := "Cooking MC's like a pound of bacon"
	if output.Text != expected {
		test.Errorf("expected the input to decode to %v but got %q instead", expected, output.Text)
	}

	if output.Key != 'X' {
		test.Errorf("expected the key to be guessed as 'X' but was %q", output.Key)
	}
}

// Challenge 4 is to locate the 1 string within 60 hex snippets that is a
// an english string xor'd with a 1 byte key
// http://cryptopals.com/sets/1/challenges/4/
func TestSet1Challenge4(test *testing.T) {
	text := get("http://cryptopals.com/static/challenge-data/4.txt")
	expected := "Now that the party is jumping\n"
	// BUG(ian) assumes that 1 and only 1 string in the input text, should probably accumulate all
	// qualifying strings in a slice
	var found string
	for _, code := range strings.Split(text, "\n") {
		s := vigenere.CrackSimple(encodings.HexToBytes(code))
		if s.Score < 0.025 {
			found = s.Text
		}
	}

	if found != expected {
		test.Errorf("expected clear text to be found with message %v but found %q", expected, found)
	}
}

// Challenge 5 is to implement a function that applies a multi byte key to a plaintext cyclically
// http://cryptopals.com/sets/1/challenges/5/
func TestSet1Challenge5(test *testing.T) {
	input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
		"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	key := []byte("ICE")
	ciphertext := vigenere.Encrypt([]byte(input), key)
	hextext := encodings.BytesToHex(ciphertext)
	if hextext != expected {
		test.Errorf("Expected %v but got %v", expected, hextext)
	}
}

// Challenge 6 requires detecting the key length of a plaintext xor'd
// with a fixed key, and then cracking that key
// http://cryptopals.com/sets/1/challenges/6/
func TestSet1Challenge6(test *testing.T) {
	ciphertext := get("http://cryptopals.com/static/challenge-data/6.txt")
	expected := whiteboy
	p := string(vigenere.Crack(encodings.Base64ToBytes(ciphertext)))
	if p != expected {
		test.Errorf("expected: %v\nbut got: %q", expected, p)
	}
}

// Challenge 7 is to find a AES ECB encrypted string within a set of strings
func TestSet1Challenge7(test *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := encodings.Base64ToBytes(get("http://cryptopals.com/static/challenge-data/7.txt"))
	decrypted := make([]byte, len(ciphertext))
	bs := aes.BlockSize()
	// use the slices like queue's and keep consuming a blocksize
	// at a time, putting them into the next slice in the destination slice
	// note: if you were to get rid of assigning decrypted to d, there would be no handle
	// to the original full slice left to return at the end of the test
	d := decrypted
	for len(ciphertext) > 0 {
		aes.Decrypt(d, ciphertext[:bs])
		//shift the decrypted and source slices start points to the next chunk
		d = d[bs:]
		ciphertext = ciphertext[bs:]
	}

	if !strings.Contains(string(decrypted), "I'm back and I'm ringin' the bell") {
		test.Errorf("invalid paintext returned from AES")
	}
}

// wrapper for getting a plaintext url, panicing if any problems come up
func get(url string) string {
	response, e := http.Get(url)
	if e != nil {
		panic(e)
	}
	defer response.Body.Close()
	bytes, e := ioutil.ReadAll(response.Body)
	if e != nil {
		panic(e)
	}
	return string(bytes)
}

const whiteboy = "I'm back and I'm ringin' the bell \n" +
	"A rockin' on the mike while the fly girls yell \n" +
	"In ecstasy in the back of me \n" +
	"Well that's my DJ Deshay cuttin' all them Z's \n" +
	"Hittin' hard and the girlies goin' crazy \n" +
	"Vanilla's on the mike, man I'm not lazy. \n" +
	"\n" +
	"I'm lettin' my drug kick in \n" +
	"It controls my mouth and I begin \n" +
	"To just let it flow, let my concepts go \n" +
	"My posse's to the side yellin', Go Vanilla Go! \n" +
	"\n" +
	"Smooth 'cause that's the way I will be \n" +
	"And if you don't give a damn, then \n" +
	"Why you starin' at me \n" +
	"So get off 'cause I control the stage \n" +
	"There's no dissin' allowed \n" +
	"I'm in my own phase \n" +
	"The girlies sa y they love me and that is ok \n" +
	"And I can dance better than any kid n' play \n" +
	"\n" +
	"Stage 2 -- Yea the one ya' wanna listen to \n" +
	"It's off my head so let the beat play through \n" +
	"So I can funk it up and make it sound good \n" +
	"1-2-3 Yo -- Knock on some wood \n" +
	"For good luck, I like my rhymes atrocious \n" +
	"Supercalafragilisticexpialidocious \n" +
	"I'm an effect and that you can bet \n" +
	"I can take a fly girl and make her wet. \n" +
	"\n" +
	"I'm like Samson -- Samson to Delilah \n" +
	"There's no denyin', You can try to hang \n" +
	"But you'll keep tryin' to get my style \n" +
	"Over and over, practice makes perfect \n" +
	"But not if you're a loafer. \n" +
	"\n" +
	"You'll get nowhere, no place, no time, no girls \n" +
	"Soon -- Oh my God, homebody, you probably eat \n" +
	"Spaghetti with a spoon! Come on and say it! \n" +
	"\n" +
	"VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n" +
	"Intoxicating so you stagger like a wino \n" +
	"So punks stop trying and girl stop cryin' \n" +
	"Vanilla Ice is sellin' and you people are buyin' \n" +
	"'Cause why the freaks are jockin' like Crazy Glue \n" +
	"Movin' and groovin' trying to sing along \n" +
	"All through the ghetto groovin' this here song \n" +
	"Now you're amazed by the VIP posse. \n" +
	"\n" +
	"Steppin' so hard like a German Nazi \n" +
	"Startled by the bases hittin' ground \n" +
	"There's no trippin' on mine, I'm just gettin' down \n" +
	"Sparkamatic, I'm hangin' tight like a fanatic \n" +
	"You trapped me once and I thought that \n" +
	"You might have it \n" +
	"So step down and lend me your ear \n" +
	"'89 in my time! You, '90 is my year. \n" +
	"\n" +
	"You're weakenin' fast, YO! and I can tell it \n" +
	"Your body's gettin' hot, so, so I can smell it \n" +
	"So don't be mad and don't be sad \n" +
	"'Cause the lyrics belong to ICE, You can call me Dad \n" +
	"You're pitchin' a fit, so step back and endure \n" +
	"Let the witch doctor, Ice, do the dance to cure \n" +
	"So come up close and don't be square \n" +
	"You wanna battle me -- Anytime, anywhere \n" +
	"\n" +
	"You thought that I was weak, Boy, you're dead wrong \n" +
	"So come on, everybody and sing this song \n" +
	"\n" +
	"Say -- Play that funky music Say, go white boy, go white boy go \n" +
	"play that funky music Go white boy, go white boy, go \n" +
	"Lay down and boogie and play that funky music till you die. \n" +
	"\n" +
	"Play that funky music Come on, Come on, let me hear \n" +
	"Play that funky music white boy you say it, say it \n" +
	"Play that funky music A little louder now \n" +
	"Play that funky music, white boy Come on, Come on, Come on \n" +
	"Play that funky music \n"
