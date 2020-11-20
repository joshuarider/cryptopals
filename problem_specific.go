package main

import (
	"math/rand"
	"strings"

	"github.com/joshuarider/cryptopals/crypto"
)

// Problem 11
func mysteryEncrypter() (func([]byte) []byte, string) {
	aesKey := crypto.RandomBytes(16)

	frontPad := crypto.RandomBytes(rand.Intn(6) + 5)
	backPad := crypto.RandomBytes(rand.Intn(6) + 5)

	if rand.Intn(2) == 0 {
		return func(in []byte) []byte {
			paddedIn := append(frontPad, in...)
			paddedIn = append(paddedIn, backPad...)
			return crypto.ECBEncryptAES(paddedIn, aesKey)
		}, "ECB"
	}

	iv := crypto.RandomBytes(16)
	return func(in []byte) []byte {
		paddedIn := append(frontPad, in...)
		paddedIn = append(paddedIn, backPad...)
		return crypto.CBCEncryptAES(paddedIn, aesKey, iv)
	}, "CBC"
}

// Problem 12
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

func appendingECBEncrypter(suffix []byte) func([]byte) []byte {
	return surroundingECBEncrypter([]byte{}, suffix)
}

// Problem 14
func surroundingECBEncrypter(prefix []byte, suffix []byte) func([]byte) []byte {
	aesKey := crypto.RandomBytes(16)

	return func(plaintext []byte) []byte {
		fullText := append(prefix, plaintext...)
		fullText = append(fullText, suffix...)

		return crypto.ECBEncryptAES(fullText, aesKey)
	}
}

// Problem 16
func cookieStringCBCEncrypter(encrypter func([]byte) []byte) func(string) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	return func(s string) []byte {
		sanitizedString := strings.ReplaceAll(s, ";", "")
		sanitizedString = strings.ReplaceAll(s, "=", "")

		return encrypter([]byte(prefix + sanitizedString + suffix))
	}
}

func cookieStringCBCDecrypter(decrypter func([]byte) []byte) func([]byte) string {
	return func(c []byte) string {
		return string(decrypter(c))
	}
}

func cookieStringCBCPair() (func(string) []byte, func([]byte) string) {
	e, d := crypto.CBCPair()

	return cookieStringCBCEncrypter(e), cookieStringCBCDecrypter(d)
}

func hasAdminClaim(cookie string) bool {
	for _, clause := range strings.Split(cookie, ";") {
		if strings.Compare("admin=true", clause) == 0 {
			return true
		}
	}
	return false
}
