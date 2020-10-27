package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/encoding"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomBytes(n int) []byte {
	bytes := make([]byte, 0, n)

	for i := 0; i < n; i++ {
		bytes = append(bytes, byte(rand.Intn(256)))
	}

	return bytes
}

func mysteryEncrypter() (func([]byte) []byte, string) {
	aesKey := randomBytes(16)

	frontPad := randomBytes(rand.Intn(6) + 5)
	backPad := randomBytes(rand.Intn(6) + 5)

	if rand.Intn(2) == 0 {
		return func(in []byte) []byte {
			paddedIn := append(frontPad, in...)
			paddedIn = append(paddedIn, backPad...)
			return crypto.ECBEncryptAES(paddedIn, aesKey)
		}, "ECB"
	}

	iv := randomBytes(16)
	return func(in []byte) []byte {
		paddedIn := append(frontPad, in...)
		paddedIn = append(paddedIn, backPad...)
		return crypto.CBCEncryptAES(paddedIn, aesKey, iv)
	}, "CBC"
}

func appendingECBEncrypter() (func([]byte) []byte, error) {
	aesKey := randomBytes(16)
	suffix, err := encoding.B64ToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	if err != nil {
		return nil, fmt.Errorf("couldn't decode B64ToBytes %v", err)
	}

	return func(plaintext []byte) []byte {
		fullText := append(plaintext, suffix...)
		return crypto.ECBEncryptAES(fullText, aesKey)
	}, nil
}

func cipherOracle(encrypter func([]byte) []byte) string {
	knownText := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	cipherText := encrypter(knownText)

	length := len(cipherText)
	matchLength := 0

	for f, s := 0, 16; s < length; f, s = f+1, s+1 {
		if cipherText[f] != cipherText[s] {
			matchLength = 0
			continue
		}

		matchLength++

		if matchLength == 16 {
			return "ECB"
		}
	}

	return "CBC"
}
