package encodings

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

// realistically {Base64,Hex}ToBytes should just return []byte, error if this
// were anything other than a learning exercise, but as is, it made for a good chance
// to get more comfortable with panic/defer/recover
func TestInvalidBase64ToBytes(test *testing.T) {
	defer checkForPanic(base64.CorruptInputError(9), test)
	Base64ToBytes("NotBase64@!")
}

func TestInvalidHexToBytes(test *testing.T) {
	defer checkForPanic(hex.InvalidByteError(0x4E), test)
	HexToBytes("NotHex")
}

func checkForPanic(v interface{}, test *testing.T) {
	if r := recover(); r != nil {
		fmt.Println(reflect.TypeOf(r))
		if v != r {
			test.Errorf("Expected to recover %v but instead got %v", v, r)
		}
	} else {
		test.Error("expected a panic, but none occured")
	}

}

func TestBase64ToBytes(test *testing.T) {
	i := "SQ=="
	o := Base64ToBytes(i)
	expected := byte(0x49)
	if o[0] != expected {
		test.Errorf("expected %v to decode to %x but got % x", i, expected, o)
	}
}

func TestBytesToBase64(test *testing.T) {
	i := []byte{0x49}
	o := BytesToBase64(i)
	expected := "SQ=="
	if o != expected {
		test.Errorf("expected %v to decode to %v but got %v", i, expected, o)
	}
}

func TestHexToBytes(test *testing.T) {
	i := "AF"
	o := HexToBytes(i)
	expected := byte(175)
	if o[0] != expected {
		test.Errorf("expected %v to decode to %x but got % v", i, expected, o)
	}
}

func TestBytesToHex(test *testing.T) {
	i := []byte{175}
	o := BytesToHex(i)
	expected := "af"
	if o != expected {
		test.Errorf("expected %v to decode to %v but got %v", i, expected, o)
	}
}
