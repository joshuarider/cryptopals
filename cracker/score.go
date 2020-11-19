package cracker

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
