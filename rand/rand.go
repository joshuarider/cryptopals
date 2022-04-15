package rand

const w uint32 = 32
const n uint32 = 624
const m uint32 = 397
const r uint32 = 31
const a uint32 = 0x9908B0DF
const u uint32 = 11
const d uint32 = 0xFFFFFFFF
const s uint32 = 7
const b uint32 = 0x9D2C5680
const t uint32 = 15
const c uint32 = 0xEFC60000
const l uint32 = 18
const f uint32 = 1812433253

type MersenneTwister struct {
	state     [n]uint32
	index     uint32
	lowerMask uint32
	upperMask uint32
}

func NewMersenneTwister() *MersenneTwister {
	mt := MersenneTwister{
		index:     n + 1,
		lowerMask: (1 << r) - 1,
		upperMask: ^((1 << r) - 1) & 0xFFFFFFFF,
	}

	return &mt
}

func (mt *MersenneTwister) Initialize(seed uint32) {
	mt.index = n
	mt.state[0] = seed

	for i := uint32(1); i < n; i++ {
		mt.state[i] = (f*(mt.state[i-1]^(mt.state[i-1]>>(w-2))) + i) & 0xFFFFFFFF
	}
}

func (mt *MersenneTwister) Rand() int32 {
	if mt.index >= n {
		if mt.index > n {
			// MT was never initialized
			mt.Initialize(uint32(5489))
		}

		mt.twist()
	}

	y := mt.state[mt.index]

	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)

	mt.index = mt.index + 1

	return int32(y)
}

func (mt *MersenneTwister) twist() {
	for i := uint32(0); i < n; i++ {
		x := (mt.state[i] & mt.upperMask) + (mt.state[(i+1)%n] & mt.lowerMask)
		xA := x >> 1

		if x%2 != 0 {
			xA = xA ^ a
		}

		mt.state[i] = mt.state[(i+m)%n] ^ xA
	}
	mt.index = 0
}

func (mt *MersenneTwister) LoadState(state [n]uint32) {
	mt.state = state
	mt.twist()
}
