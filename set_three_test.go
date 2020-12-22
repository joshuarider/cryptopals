package main

import (
	"testing"

	"github.com/joshuarider/cryptopals/crypto/padding"
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
