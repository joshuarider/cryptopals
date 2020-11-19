package cracker

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
