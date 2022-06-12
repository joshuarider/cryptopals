package main

import (
	"crypto/aes"
	"testing"

	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/crypto/xor"
	"github.com/joshuarider/cryptopals/util"
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

// 4.26 CTR bitflipping
func TestProblemTwentySix(t *testing.T) {
	e, d := cookieStringCTRPair()

	slug := string(make([]byte, 16))
	ciphertext := e(slug)

	byteStream := ciphertext[32:48]
	target := []byte("f;admin=true;a=f")
	injection := xor.Bytes(byteStream, target)

	tampered := append(append(ciphertext[0:32], injection...), ciphertext[48:]...)

	cookie := d(tampered)

	if !hasAdminClaim(cookie) {
		t.Errorf("expected 'admin=true', got %v", cookie)
	}
}

// 4.27 Recover the key from CBC with IV=Key
func TestProblemTwentySeven(t *testing.T) {
	key, e, d := cookieStringCBCPairWithKeyAsIV()
	ciphertext := e("abcdef")

	frankencipher := ciphertext[0:16]
	frankencipher = append(frankencipher, make([]byte, 16)...)
	frankencipher = append(frankencipher, ciphertext[0:16]...)
	frankencipher = append(frankencipher, ciphertext[64:]...)

	plaintext := d(frankencipher)

	recovered := xor.Bytes(plaintext[0:16], plaintext[32:48])

	if !util.Compare(key, recovered) {
		t.Errorf("wanted: %v, got: %v", key, recovered)
	}
}
