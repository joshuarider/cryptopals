package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"testing"

	"github.com/joshuarider/cryptopals/cracker"
	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/crypto/padding"
	"github.com/joshuarider/cryptopals/crypto/xor"
	"github.com/joshuarider/cryptopals/encoding"
)

// 2.9 Implement PKCS#7 padding
func TestProblemNine(t *testing.T) {
	testSubmarine := []byte("YELLOW SUBMARINE")

	padTable := []struct {
		size int
		want string
	}{{
		size: 10,
		want: "YELLOW SUBMARINE\x04\x04\x04\x04",
	}, {
		size: 11,
		want: "YELLOW SUBMARINE\x06\x06\x06\x06\x06\x06",
	}, {
		size: 13,
		want: "YELLOW SUBMARINE\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",
	}, {
		size: 16,
		want: "YELLOW SUBMARINE",
	}, {
		size: 18,
		want: "YELLOW SUBMARINE\x02\x02",
	}}

	for _, test := range padTable {
		got := string(padding.PKCS7Pad(testSubmarine, test.size))

		if test.want != got {
			t.Errorf("Pad error: want = %v, got = %v", test.want, got)
		}
	}

	unpadTable := []struct {
		input string
		want  string
	}{{
		input: "\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f",
		want:  "",
	}, {
		input: "\x01",
		want:  "",
	}, {
		input: "A potential false alarm\x02",
		want:  "A potential false alarm\x02",
	}}

	for _, test := range unpadTable {
		got := string(padding.PKCS7Unpad([]byte(test.input)))

		if test.want != got {
			t.Errorf("Unpad error: want = %v, got = %v", test.want, got)
		}
	}
}

// 2.10 Implement CBC mode
func TestProblemTen(t *testing.T) {
	inputFile := "input/2/10.txt"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("Unable to open: %s, %v", inputFile, err)
	}
	defer file.Close()

	b64Text := ""

	s := bufio.NewScanner(file)

	for s.Scan() {
		b64Text += s.Text()
	}

	cipherBytes, err := encoding.B64ToBytes(b64Text)
	if err != nil {
		t.Fatalf("error decoding B64ToBytes: %v\n", err)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)

	decrypted := crypto.CBCDecryptAES(cipherBytes, key, iv)

	if got := string(decrypted); got != FUNKY_MUSIC {
		t.Errorf("wanted the lyrics to Play That Funky Music, got = %#v", got)
	}
}

// 2.11 An ECB/CBC detection oracle
func TestProblemEleven(t *testing.T) {
	for i := 0; i < 10; i++ {
		crypter, actual := mysteryEncrypter()
		prediction := cipherOracle(crypter)

		if prediction != actual {
			t.Errorf("prediction: %s, actual: %s", prediction, actual)
		}
	}
}

// 2.12 Byte-at-a-time ECB Decryption (Simple)
func TestProblemTwelve(t *testing.T) {
	suffix, err := encoding.B64ToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	if err != nil {
		t.Fatalf("couldn't decode B64ToBytes %v", err)
	}

	crypter := appendingECBEncrypter(suffix)

	if encryptionMode := cipherOracle(crypter); encryptionMode != "ECB" {
		t.Fatalf("wanted encryptionMode = ECB, got %s", encryptionMode)
	}

	blockSize := findBlockSize(crypter)

	if blockSize != 16 {
		t.Fatalf("wanted blockSize = 16, got %d", blockSize)
	}

	want := string(suffix)

	if got := string(cracker.CrackAppendedECB(crypter, blockSize)); want != got {
		t.Errorf("want: %v, got: %v", want, got)
	}
}

// 2.13 ECB cut-and-paste
func TestProblemThirteen(t *testing.T) {
	encrypter, decrypter := crypto.ECBPair()

	// Ten character email address fills out the first block and lets the second block just be...
	emailBlockPad := []byte("aa@bar.com")

	// ... a "pre-PKCS#7 padded" block that just says "admin"
	adminDummy := []byte{97, 100, 109, 105, 110, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}

	evilEmail := string(append(emailBlockPad, adminDummy...))

	testProfile := profileFor(evilEmail)

	// Extract the second block that just says "admin"
	adminBlock := encrypter([]byte(testProfile.toCookie()))[16:32]

	// Thirteen character email allows the third block of the ciphertext to just be the user's role
	attackerEmail := "josh@evil.com"
	attackerProfile := profileFor(attackerEmail)

	cryptedAttackerCookie := encrypter([]byte(attackerProfile.toCookie()))

	// Stitch our crafted "admin" block onto the first two blocks
	frankenCiphertext := append(cryptedAttackerCookie[:32], adminBlock...)

	want := fmt.Sprintf("email=%s&uid=10&role=admin", attackerEmail)

	if got := string(decrypter(frankenCiphertext)); got != want {
		t.Errorf("want: %s, got: %s", want, got)
	}
}

// 2.14 Byte-at-a-time ECB decryption (Harder)
func TestProblemFourteen(t *testing.T) {
	prefix := crypto.RandomBytes(rand.Intn(6) + 5)
	suffix, err := encoding.B64ToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	if err != nil {
		t.Fatalf("couldn't decode B64ToBytes %v", err)
	}

	encrypter := surroundingECBEncrypter(prefix, suffix)

	want := string(suffix)

	if got := string(cracker.CrackSurroundedECB(encrypter, 16)); want != got {
		t.Errorf("want: %v, got: %v", want, got)
	}
}

// 2.15 PKCS#7 padding validation
func TestProblemFifteen(t *testing.T) {
	padTable := []struct {
		input string
		want  bool
	}{{
		input: "YELLOW\x04\x04\x04\x04",
		want:  true,
	}, {
		input: "YELLOW SUBMA\x01",
		want:  true,
	}, {
		input: "YELLOW SUBMARINE",
		want:  false,
	}, {
		input: "YELLOW SUBMARINE\x02\x02",
		want:  true,
	}, {
		input: "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
		want:  true,
	}, {
		input: "YELLOW SUBMARINE\x04\x04\x04",
		want:  false,
	}, {
		input: "YELLOW SUBMARINE\x00\x01\x02\x03",
		want:  false,
	}, {
		input: "YELLOW SUBMARINE\x04\x04\x03\x04",
		want:  false,
	}, {
		input: "",
		want:  true, // this may be incorrect
	}}

	for _, test := range padTable {
		got := padding.IsValidPKCS7([]byte(test.input))

		if test.want != got {
			t.Errorf("Pad error for %v: want = %v, got = %v", test.input, test.want, got)
		}
	}
}

// 2.16 CBC bitflipping attack
func TestProblemSixteen(t *testing.T) {
	e, d := cookieStringCBCPair()

	// fill out all of third block for `userdata`
	ciphertext := e("YELLOW SUBMARINE")

	knownSuffixBlock := []byte(";comment2=%20lik")
	desiredSuffixBlock := []byte(";admin=true;foo=")
	desiredDiff := xor.Bytes(knownSuffixBlock, desiredSuffixBlock)

	evilUserdata := xor.Bytes(ciphertext[32:48], desiredDiff)

	// replace userdata with our evil block
	evilCiphertext := append(ciphertext[:32], evilUserdata...)
	evilCiphertext = append(evilCiphertext, ciphertext[48:]...)

	if plaintext := d(evilCiphertext); !hasAdminClaim(plaintext) {
		t.Errorf("cookie string did not contain admin clause: %s", plaintext)
	}
}
