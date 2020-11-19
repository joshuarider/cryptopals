package crypto

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RandomBytes(n int) []byte {
	bytes := make([]byte, n)

	// TODO: use crypto/rand
	rand.Read(bytes)

	return bytes
}
