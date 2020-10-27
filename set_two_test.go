package main

import (
	"bufio"
	"os"
	"testing"

	"github.com/joshuarider/cryptopals/crypto"
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
		got := string(crypto.PKCSPad(testSubmarine, test.size))

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
		got := string(crypto.PKCSUnpad([]byte(test.input)))

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
