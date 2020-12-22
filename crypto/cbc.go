package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/joshuarider/cryptopals/crypto/padding"
	"github.com/joshuarider/cryptopals/crypto/xor"
)

func CBCDecryptAES(ciphertext []byte, key []byte, iv []byte) []byte {
	cipher, _ := aes.NewCipher(key)

	plaintext := CBCDecryptPadded(ciphertext, cipher, iv)

	return padding.PKCS7Unpad(plaintext)
}

func CBCDecryptPadded(ciphertext []byte, cipher cipher.Block, iv []byte) []byte {
	blockSize := len(iv)
	plaintext := make([]byte, 0, len(ciphertext))
	plainBlock := make([]byte, blockSize)

	for bs, be := 0, blockSize; bs < len(ciphertext); bs, be = bs+blockSize, be+blockSize {
		cipher.Decrypt(plainBlock, ciphertext[bs:be])

		plaintext = append(plaintext, xor.Bytes(iv, plainBlock)...)
		iv = ciphertext[bs:be]
	}

	return plaintext
}

func CBCEncryptAES(plainText []byte, key []byte, iv []byte) []byte {
	blockSize := len(iv)

	paddedText := padding.PKCS7Pad(plainText, blockSize)
	cipher, _ := aes.NewCipher(key)
	return CBCEncryptPadded(paddedText, cipher, iv)
}

func CBCEncryptPadded(paddedText []byte, cipher cipher.Block, iv []byte) []byte {
	blockSize := len(iv)
	cipherText := make([]byte, 0, len(paddedText))

	encryptedChunk := make([]byte, blockSize)

	for bs, be := 0, blockSize; bs < len(paddedText); bs, be = bs+blockSize, be+blockSize {
		block := paddedText[bs:be]

		cipher.Encrypt(encryptedChunk, xor.Bytes(iv, block))

		cipherText = append(cipherText, encryptedChunk...)

		iv = encryptedChunk
	}

	return cipherText
}

func CBCEncrypter(key []byte, iv []byte) func([]byte) []byte {
	return func(plaintext []byte) []byte {
		return CBCEncryptAES(plaintext, key, iv)
	}
}

func CBCDecrypter(key []byte, iv []byte) func([]byte) []byte {
	return func(ciphertext []byte) []byte {
		return CBCDecryptAES(ciphertext, key, iv)
	}
}

func CBCPair() (e, d func([]byte) []byte) {
	aesKey := RandomBytes(16)
	iv := make([]byte, 16)

	e = CBCEncrypter(aesKey, iv)
	d = CBCDecrypter(aesKey, iv)

	return
}
