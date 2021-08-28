package padding

import "errors"

func PKCS7Pad(chunk []byte, targetLength int) []byte {
	overhang := len(chunk) % targetLength

	pad := uint8(targetLength - overhang)

	for i := uint8(0); i < pad; i++ {
		chunk = append(chunk, byte(pad))
	}

	return chunk
}

func PKCS7Unpad(text []byte) ([]byte, error) {
	length := len(text)
	if length == 0 {
		return []byte{}, errors.New("invalid padding, length was zero")
	}

	lastByte := int(text[length-1])

	if lastByte == 0 {
		return []byte{}, errors.New("invalid padding, last byte was 0")
	}

	if lastByte > length {
		return []byte{}, errors.New("invalid padding, final byte was greater than length of string")
	}

	speculatedPadStart := length - lastByte

	for i := speculatedPadStart; i < length-1; i++ {
		if text[length-1] != text[i] {
			return []byte{}, errors.New("invalid padding")
		}
	}

	return text[:speculatedPadStart], nil
}

func IsValidPKCS7(text []byte) bool {
	_, err := PKCS7Unpad(text)

	return err == nil
}
