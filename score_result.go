package main

type ScoreResult struct {
	Score float64
	Line  []byte
}

type ScoreResults []ScoreResult

func (r ScoreResults) Len() int {
	return len(r)
}

func (r ScoreResults) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r ScoreResults) Less(i, j int) bool {
	return r[i].Score > r[j].Score
}

func (r *ScoreResults) Push(x interface{}) {
	*r = append(*r, x.(ScoreResult))
}

func (r *ScoreResults) Pop() interface{} {
	old := *r
	n := len(old)
	x := old[n-1]
	*r = old[0 : n-1]
	return x
}
