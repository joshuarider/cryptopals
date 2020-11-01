package cracker

import (
	"container/heap"
	"fmt"

	"github.com/joshuarider/cryptopals/encoding"
)

type Candidate struct {
	Score  float64
	Letter byte
}

type Scores []Candidate

func (r Scores) Len() int {
	return len(r)
}

func (r Scores) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r Scores) Less(i, j int) bool {
	return r[i].Score > r[j].Score
}

func (r *Scores) Push(x interface{}) {
	*r = append(*r, x.(Candidate))
}

func (r *Scores) Pop() interface{} {
	old := *r
	n := len(old)
	x := old[n-1]
	*r = old[0 : n-1]
	return x
}

type LengthCandidate struct {
	HammingDistance float64
	Length          int
}

type LengthCandidateHeap []LengthCandidate

func (h LengthCandidateHeap) Len() int {
	return len(h)
}

func (h LengthCandidateHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h LengthCandidateHeap) Less(i, j int) bool {
	return h[i].HammingDistance < h[j].HammingDistance
}

func (h *LengthCandidateHeap) Push(x interface{}) {
	*h = append(*h, x.(LengthCandidate))
}

func (h *LengthCandidateHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

var (
	letterFreq = map[byte]float64{
		byte(65): 0.08167, // 'A'
		byte(66): 0.01492, // 'B'
		byte(67): 0.02782, // 'C'
		byte(68): 0.04253, // 'D'
		byte(69): 0.12702, // 'E'
		byte(70): 0.02228, // 'F'
		byte(71): 0.02015, // 'G'
		byte(72): 0.06094, // 'H'
		byte(73): 0.06966, // 'I'
		byte(74): 0.00153, // 'J'
		byte(75): 0.00772, // 'K'
		byte(76): 0.04025, // 'L'
		byte(77): 0.02406, // 'M'
		byte(78): 0.06749, // 'N'
		byte(79): 0.07507, // 'O'
		byte(80): 0.01929, // 'P'
		byte(81): 0.00095, // 'Q'
		byte(82): 0.05987, // 'R'
		byte(83): 0.06327, // 'S'
		byte(84): 0.09056, // 'T'
		byte(85): 0.02758, // 'U'
		byte(86): 0.00978, // 'V'
		byte(87): 0.02360, // 'W'
		byte(88): 0.00150, // 'X'
		byte(89): 0.01974, // 'Y'
		byte(90): 0.00074, // 'Z'
		byte(32): 0.17000, // 'SPACE'
		byte(33): 0.17000, // '!'
		byte(34): 0.00000, // '"'
		byte(39): 0.00000, // "'"
		byte(44): 0.00000, // ','
		byte(45): 0.00000, // '-'
		byte(46): 0.00000, // '.'
		byte(48): 0.00000, // '0'
		byte(49): 0.00000, // '1'
		byte(50): 0.00000, // '2'
		byte(51): 0.00000, // '3'
		byte(52): 0.00000, // '4'
		byte(53): 0.00000, // '5'
		byte(54): 0.00000, // '6'
		byte(55): 0.00000, // '7'
		byte(56): 0.00000, // '8'
		byte(57): 0.00000, // '9'
		byte(58): 0.00000, // ':'
		byte(59): 0.00000, // ';'
		byte(10): 0.00000, // '\n'
		byte(13): 0.00000, // '\r'
	}
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
		candidate := encoding.XorSingleByte(b, i)
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

			knownPad := append(input, revealedBytes...)
			knownTargetStart := len(knownPad) - (blockSize - 1)
			known := knownPad[knownTargetStart : knownTargetStart+blockSize-1]

			target := cipherText[blockStart : blockStart+blockSize]

			discoveredChar, err := bruteTrailingECBByte(encrypter, known, target)
			if err != nil {
				// no match found due to final byte in `known` changing as a result of difference in size of padding
				return revealedBytes[:len(revealedBytes)-1]
			}

			revealedBytes = append(revealedBytes, discoveredChar)
		}
	}

	return revealedBytes
}

func bruteTrailingECBByte(encrypter func([]byte) []byte, known []byte, target []byte) (byte, error) {

	blockStart := (len(known) / 16) * 16

	for c := uint8(0); c <= 254; c++ {
		testCase := append(known, c)
		out := encrypter(testCase)

		if compare(out[blockStart:blockStart+16], target) {
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
