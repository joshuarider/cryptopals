package crypto

import (
	"crypto/aes"

	"github.com/joshuarider/cryptopals/crypto/padding"
	"github.com/joshuarider/cryptopals/encoding"
)

func CBCDecryptAES(cipherText []byte, key []byte, iv []byte) []byte {
	blockSize := len(iv)

	cipher, _ := aes.NewCipher(key)

	plainText := make([]byte, 0, len(cipherText))
	plainBlock := make([]byte, blockSize)

	for bs, be := 0, blockSize; bs < len(cipherText); bs, be = bs+blockSize, be+blockSize {
		cipher.Decrypt(plainBlock, cipherText[bs:be])

		plainText = append(plainText, encoding.XorBytes(iv, plainBlock)...)
		iv = cipherText[bs:be]
	}

	return padding.PKCS7Unpad(plainText)
}

func CBCEncryptAES(plainText []byte, key []byte, iv []byte) []byte {
	blockSize := len(iv)

	paddedText := padding.PKCS7Pad(plainText, blockSize)
	cipherText := make([]byte, 0, len(paddedText))

	cipher, _ := aes.NewCipher(key)
	encryptedChunk := make([]byte, blockSize)

	for bs, be := 0, blockSize; bs < len(paddedText); bs, be = bs+blockSize, be+blockSize {
		block := paddedText[bs:be]

		cipher.Encrypt(encryptedChunk, encoding.XorBytes(iv, block))

		cipherText = append(cipherText, encryptedChunk...)

		iv = encryptedChunk
	}

	return cipherText
}

func CBCEncrypter(key []byte) func([]byte) []byte {
	iv := make([]byte, 16)
	return func(plaintext []byte) []byte {
		return CBCEncryptAES(plaintext, key, iv)
	}
}

func CBCDecrypter(key []byte) func([]byte) []byte {
	iv := make([]byte, 16)
	return func(ciphertext []byte) []byte {
		return CBCDecryptAES(ciphertext, key, iv)
	}
}

func CBCPair() (e, d func([]byte) []byte) {
	aesKey := RandomBytes(16)

	e = CBCEncrypter(aesKey)
	d = CBCDecrypter(aesKey)

	return
}
