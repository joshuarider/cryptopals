package crypto

import (
	"crypto/aes"

	"github.com/joshuarider/cryptopals/crypto/padding"
)

func ECBDecryptAES(cipherText []byte, key []byte) []byte {
	plainText := make([]byte, len(cipherText))
	cipher, _ := aes.NewCipher(key)
	blockSize := 16 // may need to parameterize this

	for bs, be := 0, blockSize; bs < len(cipherText); bs, be = bs+blockSize, be+blockSize {
		cipher.Decrypt(plainText[bs:be], cipherText[bs:be])
	}

	unpadded, _ := padding.PKCS7Unpad(plainText)

	return unpadded
}

func ECBEncryptAES(plainText []byte, key []byte) []byte {
	blockSize := 16
	paddedText := padding.PKCS7Pad(plainText, blockSize)
	cipherText := make([]byte, len(paddedText))
	cipher, _ := aes.NewCipher(key)

	for bs, be := 0, blockSize; bs < len(cipherText); bs, be = bs+blockSize, be+blockSize {
		cipher.Encrypt(cipherText[bs:be], paddedText[bs:be])
	}

	return cipherText
}

func ECBEncrypter(key []byte) func([]byte) []byte {
	return func(plaintext []byte) []byte {
		return ECBEncryptAES(plaintext, key)
	}
}

func ECBDecrypter(key []byte) func([]byte) []byte {
	return func(ciphertext []byte) []byte {
		return ECBDecryptAES(ciphertext, key)
	}
}

func ECBPair() (e, d func([]byte) []byte) {
	aesKey := RandomBytes(16)

	e = ECBEncrypter(aesKey)
	d = ECBDecrypter(aesKey)

	return
}
