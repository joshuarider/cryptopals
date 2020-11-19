package main

func cipherOracle(encrypter func([]byte) []byte) string {
	knownText := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
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
