package main

import (
	"crypto/aes"
	"testing"

	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/crypto/padding"
	"github.com/joshuarider/cryptopals/encoding"
	"github.com/joshuarider/cryptopals/util"
)

// 3.17 The CBC padding oracle
func TestProblemSeventeen(t *testing.T) {
	ciphertext, cipher, iv, want := encryptForCBCOracle()
	paddedCrackedText := CBCPaddingOracle(ciphertext, cipher, iv)
	got := padding.PKCS7Unpad(paddedCrackedText)

	if !util.Compare(want, got) {
		t.Errorf("Did not find expected plaintext. want: %s, got: %s", want, got)
	}
}

// 3.18 Implement CTR, the stream cipher mode
func TestProblemEighteen(t *testing.T) {
	want := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	ciphertext, _ := encoding.B64ToBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

	key := []byte("YELLOW SUBMARINE")
	cipher, _ := aes.NewCipher(key)
	ctr := crypto.NewCTR(cipher, 0)

	if got := string(ctr.Encrypt(ciphertext)); got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}
