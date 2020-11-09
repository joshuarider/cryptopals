package crypto

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

func ValidatePKCS7Padding(text []byte, blockSize int) bool {
	length := len(text)
	if length == 0 {
		return true
	}

	if length%blockSize != 0 {
		return false
	}

	lastByte := int(text[length-1])

	if lastByte >= blockSize {
		return true
	}

	lastBlock := text[len(text)-blockSize:]

	speculatedPadStart := blockSize - lastByte

	for i := speculatedPadStart; i < blockSize-1; i++ {
		if lastBlock[blockSize-1] != lastBlock[i] {
			return false
		}
	}

	return true
}
