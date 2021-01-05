package crypto

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/joshuarider/cryptopals/crypto/xor"
)

type CTR struct {
	blockSize int
	cipher    cipher.Block
	counter   []byte
	stream    []byte
}

func NewCTR(cipher cipher.Block, nonce uint64) *CTR {
	counter := make([]byte, 16)
	binary.LittleEndian.PutUint64(counter[8:], nonce)

	return &CTR{
		blockSize: 16,
		cipher:    cipher,
		counter:   counter,
		stream:    []byte{},
	}
}

func (c *CTR) increment() {
	for i := 8; i < c.blockSize; i++ {
		c.counter[i] = c.counter[i] + 1

		if c.counter[i] != 0 {
			return
		}
	}
}

func (c *CTR) generate() {
	cipherStream := make([]byte, c.blockSize)
	c.cipher.Encrypt(cipherStream, c.counter)
	c.stream = append(c.stream, cipherStream...)

	c.increment()
}

func (c *CTR) Encrypt(in []byte) []byte {
	for len(c.stream) < len(in) {
		c.generate()
	}

	out := xor.Bytes(in, c.stream[0:len(in)])

	c.stream = c.stream[len(in):]

	return out
}
