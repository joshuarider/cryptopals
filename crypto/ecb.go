package crypto

import "crypto/aes"

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
