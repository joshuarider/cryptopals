package encoding

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
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
