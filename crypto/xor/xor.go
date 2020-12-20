package xor

import "github.com/joshuarider/cryptopals/encoding"

// Bytes xors b1 against b2
func Bytes(b1, b2 []byte) []byte {
	l := len(b1)
	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = b1[i] ^ b2[i]
	}

	return ret
}

// Hex xors hex string h1 against hex string h2
func Hex(h1, h2 string) string {
	b1, _ := encoding.HexToBytes(h1)
	b2, _ := encoding.HexToBytes(h2)
	x := Bytes(b1, b2)

	return encoding.BytesToHex(x)
}

// RepeatedKey xors in against key, going back to the beginning of key when the end of key is reached
func RepeatedKey(in []byte, key []byte) []byte {
	length := len(in)
	keyLength := len(key)
	out := make([]byte, length)

	for i := 0; i < length; i++ {
		out[i] = in[i] ^ key[i%keyLength]
	}

	return out
}

// SingleByte xors every byte in b against c
func SingleByte(b []byte, c byte) []byte {
	l := len(b)
	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = b[i] ^ c
	}

	return ret
}
