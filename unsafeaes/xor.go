package unsafeaes

import (
	"fmt"
)

func xor(a []byte, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("array a and b had differing lengths (%v and %v respectievely", len(a), len(b)))
	}

	l := len(a)
	out := make([]byte, l)
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}
