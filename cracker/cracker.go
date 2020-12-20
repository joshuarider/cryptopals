package cracker

import (
	"container/heap"
	"fmt"

	"github.com/joshuarider/cryptopals/crypto/xor"
)

func Score(candidate []byte) float64 {
	score := float64(0.0)
	for _, c := range candidate {
		if c >= uint8(97) && c <= uint8(122) {
			c = c - uint8(32)
		}

		rating, ok := letterFreq[c]

		if !ok {
			score -= float64(5.0)
			continue
		}

		score += rating
	}

	return score
}

// precondition: len(b1) == len(b2)
func HammingDistance(b1, b2 []byte) int {
	ones := 0

	for i := range b1 {
		b := b1[i] ^ b2[i]
		ones += countOnes(b)
	}

	return ones
}

func countOnes(b byte) int {
	i := int(b)
	ones := 0

	for i > 0 {
		ones += i % 2
		i = i >> 1
	}

	return ones
}

func BestGuess(b []byte) byte {
	sr := &Scores{}

	for i := uint8(1); i < 255; i++ {
		candidate := xor.SingleByte(b, i)
		heap.Push(sr, Candidate{Score: Score(candidate), Letter: i})
	}

	c := heap.Pop(sr).(Candidate)
	return c.Letter
}

func GuessRepeatedXorKeyLength(b []byte) int {
	lch := &LengthCandidateHeap{}

	for i := 2; i < 41; i++ {
		hamCount := len(b) / (2 * i)
		totalHam := 0.0
		for idx := 0; idx+(2*i) < len(b); idx = idx + (2 * i) {
			totalHam += float64(HammingDistance(b[idx:idx+i], b[idx+i:idx+(2*i)])) / float64(i)
		}
		heap.Push(lch, LengthCandidate{Length: i, HammingDistance: float64(totalHam) / float64(hamCount)})
	}

	best := heap.Pop(lch).(LengthCandidate)

	return best.Length
}

func Transpose(bytes []byte, size int) [][]byte {
	transpositions := make([][]byte, size)

	for j := range transpositions {
		bonus := 0
		if j < len(bytes)%size {
			bonus = 1
		}

		transpositions[j] = make([]byte, len(bytes)/size+bonus)
	}

	for b := range bytes {
		transpositions[b%size][b/size] = bytes[b]
	}

	return transpositions
}

func CrackAppendedECB(encrypter func([]byte) []byte, blockSize int) []byte {
	mysteryPadSize := len(encrypter([]byte{}))

	revealedBytes := []byte{}

	for blockIdx := 0; len(revealedBytes) < mysteryPadSize; blockIdx++ {
		blockStart := blockIdx * blockSize

		for i, padSize := 0, blockSize-1; i < blockSize; i, padSize = i+1, padSize-1 {
			// could cache cipherTexts for padSizes of [0,blockSize) instead of recreating for each block
			input := make([]byte, padSize)
			cipherText := encrypter(input)

			known := append(input, revealedBytes...)
			known = known[len(known)-(blockSize-1):]

			target := cipherText[blockStart : blockStart+blockSize]

			discoveredChar, err := bruteTrailingECBByte(encrypter, blockSize, known, target)
			if err != nil {
				// no match found due to final byte in `known` changing as a result of difference in size of padding
				return revealedBytes[:len(revealedBytes)-1]
			}

			revealedBytes = append(revealedBytes, discoveredChar)
		}
	}

	return revealedBytes
}

func CrackSurroundedECB(encrypter func([]byte) []byte, bs int) []byte {
	prefixPadSize := findPrefixPadSize(encrypter, bs)

	suffixSize := len(encrypter([]byte{})) - (bs - prefixPadSize)

	revealedBytes := []byte{}

	// Start on second block. Block 0 is prefix plus our padding
	for blockIdx := 1; len(revealedBytes) < suffixSize; blockIdx++ {
		blockStart := blockIdx * bs

		for i, padSize := 0, bs-1+prefixPadSize; i < bs; i, padSize = i+1, padSize-1 {
			// TODO fix duplication between this and CrackAppendedECB
			input := make([]byte, padSize)
			cipherText := encrypter(input)

			known := append(input, revealedBytes...)
			known = known[len(known)-(bs-1):]

			target := cipherText[blockStart : blockStart+bs]

			discoveredChar, err := bruteTrailingECBByteWithPrefix(encrypter, bs, prefixPadSize, known, target)
			if err != nil {
				// no match found due to final byte in `known` changing as a result of difference in size of padding
				return revealedBytes[:len(revealedBytes)-1]
			}

			revealedBytes = append(revealedBytes, discoveredChar)
		}
	}

	return revealedBytes
}

// Finds blockSize minus len(encrypter's prefix)
func findPrefixPadSize(encrypter func([]byte) []byte, bs int) int {
	testPadSize := bs * 3
	testBlock := make([]byte, testPadSize)

	encryptedTest := encrypter(testBlock)

	for compare(encryptedTest[bs:bs*2], encryptedTest[bs*2:bs*3]) {
		testBlock = testBlock[:len(testBlock)-1]
		encryptedTest = encrypter(testBlock)
	}

	return len(testBlock) + 1 - (2 * bs)
}

func bruteTrailingECBByte(encrypter func([]byte) []byte, bs int, known []byte, target []byte) (byte, error) {
	for c := uint8(0); c <= 254; c++ {
		testCase := append(known, c)
		out := encrypter(testCase)

		if compare(out[:bs], target) {
			return c, nil
		}
	}

	return 0, fmt.Errorf("failed to brute ECB block, known: %v, target: %v", known, target)
}

func bruteTrailingECBByteWithPrefix(encrypter func([]byte) []byte, bs int, prefixPadSize int, known []byte, target []byte) (byte, error) {
	base := make([]byte, prefixPadSize)
	base = append(base, known...)
	for c := uint8(0); c <= 254; c++ {
		testCase := append(base, c)
		out := encrypter(testCase)

		// TODO unify this with bruteTrailingECBByte
		// we get away with this because we know prefix is always smaller than a block
		if compare(out[bs:bs+bs], target) {
			return c, nil
		}
	}

	return 0, fmt.Errorf("failed to brute ECB block, known: %v, target: %v", known, target)
}

func compare(s1 []byte, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			return false
		}
	}

	return true
}

func min(a int, b int) int {
	if a < b {
		return a
	}

	return b
}
