package main

import (
	"math/rand"
	"time"

	"github.com/joshuarider/cryptopals/crypto"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomBytes(n int) []byte {
	bytes := make([]byte, 0, n)

	// TODO: use crypto/rand
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

func ECBEncrypter(key []byte) func([]byte) []byte {
	return func(plaintext []byte) []byte {
		return crypto.ECBEncryptAES(plaintext, key)
	}
}

func ECBDecrypter(key []byte) func([]byte) []byte {
	return func(ciphertext []byte) []byte {
		return crypto.ECBDecryptAES(ciphertext, key)
	}
}

func ECBPair() (e, d func([]byte) []byte) {
	aesKey := randomBytes(16)

	e = ECBEncrypter(aesKey)
	d = ECBDecrypter(aesKey)

	return
}

func appendingECBEncrypter(suffix []byte) func([]byte) []byte {
	return surroundingECBEncrypter([]byte{}, suffix)
}

func surroundingECBEncrypter(prefix []byte, suffix []byte) func([]byte) []byte {
	aesKey := randomBytes(16)

	return func(plaintext []byte) []byte {
		fullText := append(prefix, plaintext...)
		fullText = append(fullText, suffix...)

		return crypto.ECBEncryptAES(fullText, aesKey)
	}
}

func findBlockSize(encrypter func([]byte) []byte) int {
	inputBytes := []byte{}
	base := len(encrypter(inputBytes))
	cipherLength := base

	for base == cipherLength {
		inputBytes = append(inputBytes, byte(0x41))

		cipherLength = len(encrypter(inputBytes))
	}

	return cipherLength - base
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
