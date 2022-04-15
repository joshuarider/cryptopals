package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/crypto/padding"
	"github.com/joshuarider/cryptopals/encoding"
	pals_rand "github.com/joshuarider/cryptopals/rand"
	"github.com/joshuarider/cryptopals/util"
)

// Problem 11
func mysteryEncrypter() (func([]byte) []byte, string) {
	aesKey := crypto.RandomBytes(16)

	frontPad := crypto.RandomBytes(rand.Intn(6) + 5)
	backPad := crypto.RandomBytes(rand.Intn(6) + 5)

	if rand.Intn(2) == 0 {
		return func(in []byte) []byte {
			paddedIn := append(frontPad, in...)
			paddedIn = append(paddedIn, backPad...)
			return crypto.ECBEncryptAES(paddedIn, aesKey)
		}, "ECB"
	}

	iv := crypto.RandomBytes(16)
	return func(in []byte) []byte {
		paddedIn := append(frontPad, in...)
		paddedIn = append(paddedIn, backPad...)
		return crypto.CBCEncryptAES(paddedIn, aesKey, iv)
	}, "CBC"
}

// Problem 12
func findBlockSize(encrypter func([]byte) []byte) int {
	inputBytes := []byte{}
	base := len(encrypter(inputBytes))
	cipherLength := base

	for base == cipherLength {
		inputBytes = append(inputBytes, byte(0x41))

		cipherLength = len(encrypter(inputBytes))
	}

	return cipherLength - base
}

func appendingECBEncrypter(suffix []byte) func([]byte) []byte {
	return surroundingECBEncrypter([]byte{}, suffix)
}

// Problem 14
func surroundingECBEncrypter(prefix []byte, suffix []byte) func([]byte) []byte {
	aesKey := crypto.RandomBytes(16)

	return func(plaintext []byte) []byte {
		fullText := append(prefix, plaintext...)
		fullText = append(fullText, suffix...)

		return crypto.ECBEncryptAES(fullText, aesKey)
	}
}

// Problem 16
func cookieStringCBCEncrypter(encrypter func([]byte) []byte) func(string) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	return func(s string) []byte {
		sanitizedString := strings.ReplaceAll(s, ";", "")
		sanitizedString = strings.ReplaceAll(s, "=", "")

		return encrypter([]byte(prefix + sanitizedString + suffix))
	}
}

func cookieStringCBCDecrypter(decrypter func([]byte) []byte) func([]byte) string {
	return func(c []byte) string {
		return string(decrypter(c))
	}
}

func cookieStringCBCPair() (func(string) []byte, func([]byte) string) {
	e, d := crypto.CBCPair()

	return cookieStringCBCEncrypter(e), cookieStringCBCDecrypter(d)
}

func hasAdminClaim(cookie string) bool {
	for _, clause := range strings.Split(cookie, ";") {
		if strings.Compare("admin=true", clause) == 0 {
			return true
		}
	}
	return false
}

// Problem 17
func encryptForCBCOracle() ([]byte, cipher.Block, []byte, []byte) {
	targets := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	plaintext, _ := encoding.B64ToBytes(targets[rand.Intn(len(targets))])
	paddedText := padding.PKCS7Pad(plaintext, 16)
	cipher, _ := aes.NewCipher(crypto.RandomBytes(16))
	iv := crypto.RandomBytes(16)

	ciphertext := crypto.CBCEncryptPadded(paddedText, cipher, iv)

	return ciphertext, cipher, iv, plaintext
}

func paddingOracleCheck(ciphertext []byte, cipher cipher.Block, iv []byte) bool {
	plaintext := crypto.CBCDecryptPadded(ciphertext, cipher, iv)

	return padding.IsValidPKCS7(plaintext)
}

func bruteByte(target []byte, cipher cipher.Block, ivStub []byte) byte {
	preStub := make([]uint8, 16-len(ivStub))
	evilIv := append(preStub, ivStub...)
	targetIdx := len(preStub) - 1

	for i := uint8(0); ; i++ {
		evilIv[targetIdx] = i

		if paddingOracleCheck(target, cipher, evilIv) {
			// `i ^ uint8(len(ivStub)+1)` gives us the value of the byte in the
			// intermediate state when the ciphertext has been through the AES decrypt
			// process, but has not yet gone through the CBC xor.
			return i ^ uint8(len(ivStub)+1)
		}

		if i == uint8(255) {
			break
		}
	}

	// TODO error case
	fmt.Println("fail")
	return 0
}

func makeEvilIV(known []byte, iv []byte) []byte {
	padStart := 16 - len(known)
	padByte := uint8(len(known) + 1)
	evilIV := make([]byte, len(known))

	for i := range known {
		// `iv[i+padStart] ^ known[i]` leaves us with the byte found in the intermediate state
		// of CBC decryption, when the AES decrypt has taken place, but the CBC xor has not.
		// Xor-ing the intermediate byte against our desired pad byte leaves us with a value
		// that will generate the desired pad byte when xor'd against the intermediate byte.
		// ie. when "x ^ y = z", then "x ^ z = y"
		evilIV[i] = iv[i+padStart] ^ known[i] ^ padByte
	}

	return evilIV
}

func crackCBCBlock(target []byte, cipher cipher.Block, iv []byte) []byte {
	known := []byte{}

	for i := len(iv) - 1; i >= 0; i-- {
		evilIV := makeEvilIV(known, iv)
		foundByte := bruteByte(target, cipher, evilIV) ^ iv[i]
		known = append([]byte{foundByte}, known...)
	}

	return known
}

func CBCPaddingOracle(ciphertext []byte, cipher cipher.Block, iv []byte) []byte {
	found := []byte{}

	for i := 0; i < len(ciphertext); i = i + 16 {
		target := ciphertext[i : i+16]
		b := crackCBCBlock(target, cipher, iv)
		found = append(found, b...)
		iv = target
	}

	return found
}

// Problem 19
func ReUseCTRSeed() {
	inputFile := "input/3/19.txt"

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Unable to open: %s, %v\n", inputFile, err)
		file.Close()
		os.Exit(1)
	}
	defer file.Close()

	cipher, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		bytes, err := encoding.B64ToBytes(scanner.Text())
		if err != nil {
			fmt.Println("Failed to base64 decode. Exiting.")
			os.Exit(1)
		}

		encrypter := crypto.NewCTR(cipher, uint64(0))

		s := make([]string, len(bytes))
		for i, byte := range encrypter.Encrypt(bytes) {
			s[i] = fmt.Sprintf("%d", byte)
		}

		fmt.Printf("[%s],\n", strings.Join(s, ", "))
	}
}

// Problem 23
func untemperRightShift(y uint32, shiftSize uint32, mask uint32) uint32 {
	discovered := y

	for knownBits := shiftSize; knownBits < 32; knownBits += shiftSize {
		discovered = y ^ ((discovered >> shiftSize) & mask)
	}

	return discovered
}

func untemperLeftShift(y uint32, shiftSize uint32, mask uint32) uint32 {
	discovered := y

	for knownBits := shiftSize; knownBits < 32; knownBits += shiftSize {
		discovered = y ^ ((discovered << shiftSize) & mask)
	}

	return discovered
}

func untemperMT(t uint32) uint32 {
	t = untemperRightShift(t, 18, 0xFFFFFFFF)
	t = untemperLeftShift(t, 15, 0xEFC60000)
	t = untemperLeftShift(t, 7, 0x9D2C5680)
	t = untemperRightShift(t, 11, 0xFFFFFFFF)

	return t
}

// Problem 24
func prependJunk(base []byte) []byte {
	letters := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	in := make([]byte, rand.Intn(40))

	for i := 0; i < len(in); i++ {
		in[i] = letters[rand.Intn(len(letters))]
	}

	in = append(in, base...)
	return in
}

func brute16BitMTStream(target []byte) (uint32, error) {
	sample := make([]byte, len(target)-14)
	sample = append(sample, []byte("AAAAAAAAAAAAAA")...)

	for i := uint32(0); i < uint32(math.Pow(2, 16)); i++ {
		decryptStream := crypto.NewMTStream(i)
		candidate := decryptStream.Encrypt(sample)

		if util.Compare(candidate[len(sample)-14:], target[len(sample)-14:]) {
			return i, nil
		}
	}

	return 0, errors.New("No match found")
}

func seedToPasswordResetToken(seed uint32) string {
	twister := pals_rand.NewMersenneTwister()
	twister.Initialize(seed)
	token := make([]byte, 16)

	for i := 0; i < 16; i = i + 4 {
		binary.LittleEndian.PutUint32(token[i:i+4], uint32(twister.Rand()))
	}

	return encoding.BytesToHex(token)
}

func bruteTimeSeed(token string) (uint32, error) {
	rawToken, _ := encoding.HexToBytes(token)

	twister := pals_rand.NewMersenneTwister()

	// since Apr 2022
	for i := uint32(1648771201); i <= uint32(time.Now().Unix()); i++ {
		twister.Initialize(i)

		if checkSeed(rawToken, twister) {
			return i, nil
		}
	}

	return 0, errors.New("we missed")
}

func checkSeed(candidate []byte, twister *pals_rand.MersenneTwister) bool {
	if len(candidate) == 0 {
		return true
	}

	if uint32(twister.Rand()) == binary.LittleEndian.Uint32(candidate[0:4]) {
		return checkSeed(candidate[4:], twister)
	}

	return false
}
