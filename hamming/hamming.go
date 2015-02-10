// Package hamming contains functions for calculating the hamming edit distance between
// different bytes and byte arrays
package hamming

// Distance calculates the hamming edit distance between the 2 arrays (a & b)
// both a and b must be of the same length or a panic will ensue
func Distance(a []byte, b []byte) int {
	if len(a) != len(b) {
		// TODO this should reall just use a multiple return and include an Error object
		// even if its going to panic, it should really be pancing with an Error object
		// not a string
		panic("cannot compute a hamming distance for arrays of differing length")
	}

	distance := 0
	for i := range a {
		distance += byteDistance(a[i], b[i])
	}
	return distance
}

// calculate the hamming distance of two bytes by xoring them and then counting
// how many bits are set to 1 in the resultant value
func byteDistance(a byte, b byte) int {
	x := a ^ b
	distance := 0
	// for each bit in a byte, shift that bit into the right most position
	// and then 0 out all other positions, yielding a 1 if that bit is 1, and a 0 otherwise
	for i := 0; i < 8; i++ {
		distance += int(x >> uint(i) & 1)
	}
	return distance
}
