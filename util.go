package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/joshuarider/pals/crypto"
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

func mysteryEncrypter() func([]byte) []byte {
	aesKey := randomBytes(16)

	frontPad := randomBytes(rand.Intn(6) + 5)
	backPad := randomBytes(rand.Intn(6) + 5)

	if rand.Intn(2) == 0 {
		fmt.Println("Encrypter under the hood: ECB")
		return func(in []byte) []byte {
			paddedIn := append(frontPad, in...)
			paddedIn = append(paddedIn, backPad...)
			return crypto.ECBEncryptAES(paddedIn, aesKey)
		}
	}

	fmt.Println("Encrypter under the hood: CBC")
	iv := randomBytes(16)
	return func(in []byte) []byte {
		paddedIn := append(frontPad, in...)
		paddedIn = append(paddedIn, backPad...)
		return crypto.CBCEncryptAES(paddedIn, aesKey, iv)
	}
}

func cipherOracle(encrypter func([]byte) []byte) string {
	testBlock := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	cipherText := encrypter(testBlock)

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
