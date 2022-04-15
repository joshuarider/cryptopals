package crypto

import (
	"encoding/binary"

	"github.com/joshuarider/cryptopals/crypto/xor"

	"github.com/joshuarider/cryptopals/rand"
)

type MTStream struct {
	twister *rand.MersenneTwister
	stream  []byte
}

func NewMTStream(seed uint32) *MTStream {
	mt := rand.NewMersenneTwister()
	mt.Initialize(seed)

	return &MTStream{
		twister: mt,
		stream:  []byte{},
	}
}

func (c *MTStream) generate(needed int) {
	var b [4]byte
	for len(c.stream) < needed {
		binary.LittleEndian.PutUint32(b[:], uint32(c.twister.Rand()))
		c.stream = append(c.stream, b[:]...)
	}
}

func (c *MTStream) Encrypt(in []byte) []byte {
	if len(c.stream) < len(in) {
		c.generate(len(in))
	}

	out := xor.Bytes(in, c.stream[0:len(in)])
	c.stream = c.stream[len(in):]

	return out
}
