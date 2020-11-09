package crypto

import (
	"crypto/aes"

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

	return PKCSUnpad(plainText)
}

func CBCEncryptAES(plainText []byte, key []byte, iv []byte) []byte {
	blockSize := len(iv)

	paddedText := PKCSPad(plainText, blockSize)
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
