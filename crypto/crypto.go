package crypto

import (
	"crypto/aes"

	"github.com/joshuarider/cryptopals/encoding"
)

func PKCSPad(chunk []byte, targetLength int) []byte {
	overhang := len(chunk) % targetLength

	if overhang == 0 {
		return chunk
	}

	pad := uint8(targetLength - overhang)

	for i := uint8(0); i < pad; i++ {
		chunk = append(chunk, byte(pad))
	}

	return chunk
}

func PKCSUnpad(text []byte) []byte {
	length := len(text)
	if length == 0 {
		return text
	}

	lastByte := int(text[length-1])

	if lastByte > length {
		return text
	}

	speculatedPadStart := length - lastByte

	for i := speculatedPadStart; i < length-1; i++ {
		if text[length-1] != text[i] {
			return text
		}
	}

	return text[:speculatedPadStart]
}

func ECBDecryptAES(cipherText []byte, key []byte) []byte {
	plainText := make([]byte, len(cipherText))
	cipher, _ := aes.NewCipher(key)
	blockSize := 16 // may need to parameterize this

	for bs, be := 0, blockSize; bs < len(cipherText); bs, be = bs+blockSize, be+blockSize {
		cipher.Decrypt(plainText[bs:be], cipherText[bs:be])
	}

	return PKCSUnpad(plainText)
}

func ECBEncryptAES(plainText []byte, key []byte) []byte {
	blockSize := 16
	paddedText := PKCSPad(plainText, blockSize)
	cipherText := make([]byte, len(paddedText))
	cipher, _ := aes.NewCipher(key)

	for bs, be := 0, blockSize; bs < len(cipherText); bs, be = bs+blockSize, be+blockSize {
		cipher.Encrypt(cipherText[bs:be], paddedText[bs:be])
	}

	return cipherText
}

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
