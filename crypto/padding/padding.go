package padding

func PKCS7Pad(chunk []byte, targetLength int) []byte {
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

func PKCS7Unpad(text []byte) []byte {
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

func IsValidPKCS7(text []byte) bool {
	length := len(text)
	if length == 0 {
		return true
	}

	lastByte := int(text[length-1])

	if lastByte > length {
		return false
	}

	speculatedPadStart := length - lastByte

	for i := speculatedPadStart; i < length-1; i++ {
		if text[length-1] != text[i] {
			return false
		}
	}

	return true
}
