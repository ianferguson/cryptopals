package hamming

import "testing"

func TestHammingDistance(test *testing.T) {
	dist := Distance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if dist != 37 {
		test.Errorf("expected a hamming distance of 37, not %v", dist)
	}
}

func TestMismatchedArrayLengths(test *testing.T) {
	defer checkForPanic("cannot compute a hamming distance for arrays of differing length", test)
	Distance([]byte("short"), []byte("real long"))
}

func checkForPanic(v interface{}, test *testing.T) {
	if r := recover(); r != nil {
		if v != r {
			test.Errorf("Expected to recover %v but instead got %v", v, r)
		}
	} else {
		test.Error("expected a panic, but none occured")
	}

}
