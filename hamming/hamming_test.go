package hamming

import (
	"testing"
)

func TestHammingDistance(test *testing.T) {
	dist := Distance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if dist != 37 {
		test.Errorf("expected a hamming distance of 37, not %v", dist)
	}
}
