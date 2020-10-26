package encoding

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBytes(s string) ([]byte, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func BytesToB64(src []byte) string {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)

	return string(dst)
}

func B64ToBytes(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}

// XorSingleByte xors every byte in b against c
func XorSingleByte(b []byte, c byte) []byte {
	l := len(b)
	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = b[i] ^ c
	}

	return ret
}

// XorBytes xors b1 against b2
func XorBytes(b1, b2 []byte) []byte {
	l := len(b1)
	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = b1[i] ^ b2[i]
	}

	return ret
}

// XorHex xors hex string h1 against hex string h2
func XorHex(h1, h2 string) string {
	b1, _ := HexToBytes(h1)
	b2, _ := HexToBytes(h2)
	x := XorBytes(b1, b2)

	return BytesToHex(x)
}

// RepeatedKeyXor xors in against key, going back to the beginning of key when the end of key is reached
func RepeatedKeyXor(in []byte, key []byte) []byte {
	length := len(in)
	keyLength := len(key)
	out := make([]byte, length)

	for i := 0; i < length; i++ {
		out[i] = in[i] ^ key[i%keyLength]
	}

	return out
}
