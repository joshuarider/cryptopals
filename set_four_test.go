package main

import (
	"crypto/aes"
	"testing"

	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/crypto/xor"
)

// 4.25 Break "random access read/write" AES CTR
func TestProblemTwentyFive(t *testing.T) {
	key := crypto.RandomBytes(16)
	cipher, _ := aes.NewCipher(key)
	ctr := crypto.NewCTR(cipher, 0)

	ciphertext := ctr.Encrypt([]byte(FUNKY_MUSIC))

	emptyBytes := make([]byte, len(ciphertext))
	keyStream := edit(ciphertext, key, 0, string(emptyBytes))
	plaintext := xor.Bytes(ciphertext, keyStream)

	if string(plaintext) != FUNKY_MUSIC {
		t.Fatalf("wanted: %v, got: %v", FUNKY_MUSIC, string(plaintext))
	}
}
