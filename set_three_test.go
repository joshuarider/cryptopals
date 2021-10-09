package main

import (
	"bufio"
	"crypto/aes"
	"math"
	math_rand "math/rand"
	"os"
	"testing"
	"time"

	"github.com/joshuarider/cryptopals/cracker"
	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/crypto/padding"
	"github.com/joshuarider/cryptopals/crypto/xor"
	"github.com/joshuarider/cryptopals/encoding"
	"github.com/joshuarider/cryptopals/rand"
	"github.com/joshuarider/cryptopals/util"
)

// 3.17 The CBC padding oracle
func TestProblemSeventeen(t *testing.T) {
	ciphertext, cipher, iv, want := encryptForCBCOracle()
	paddedCrackedText := CBCPaddingOracle(ciphertext, cipher, iv)
	got, err := padding.PKCS7Unpad(paddedCrackedText)

	if err != nil {
		t.Error(err)
	}

	if !util.Compare(want, got) {
		t.Errorf("Did not find expected plaintext. want: %s, got: %s", want, got)
	}
}

// 3.18 Implement CTR, the stream cipher mode
func TestProblemEighteen(t *testing.T) {
	want := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	ciphertext, _ := encoding.B64ToBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

	key := []byte("YELLOW SUBMARINE")
	cipher, _ := aes.NewCipher(key)
	ctr := crypto.NewCTR(cipher, 0)

	if got := string(ctr.Encrypt(ciphertext)); got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

// 3.19 Break fixed-nonce CTR mode using substitutions
// we are asked to do this one the old-fashioned way

// 3.20 Break fixed-nonce CTR statistically
func TestProblemTwenty(t *testing.T) {
	inputFile := "input/3/20.txt"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("Unable to open %s, %v\n", inputFile, err)
	}
	defer file.Close()

	cipher, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

	plaintexts := make([][]byte, 0)
	ciphertexts := make([][]byte, 0)

	shortest := math.MaxInt64

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		bytes, err := encoding.B64ToBytes(scanner.Text())
		if err != nil {
			t.Fatalf("Failed to base64 decode: %v", err)
		}

		if len(bytes) < shortest {
			shortest = len(bytes)
		}

		encrypter := crypto.NewCTR(cipher, 0)
		ciphertext := encrypter.Encrypt(bytes)

		plaintexts = append(plaintexts, bytes)
		ciphertexts = append(ciphertexts, ciphertext)
	}

	transpositions := make([][]byte, shortest)

	for _, ciphertext := range ciphertexts {
		for i, b := range ciphertext {
			if i >= shortest {
				break
			}

			transpositions[i] = append(transpositions[i], b)
		}
	}

	key := make([]byte, shortest)

	for i, transposition := range transpositions {
		key[i] = cracker.BestGuess(transposition)
	}

	for i, c := range ciphertexts {
		got := xor.Bytes(key, c[0:shortest])

		if want := plaintexts[i][0:shortest]; !util.Compare(want, got) {
			t.Errorf("wanted %s, got %s", want, got)
		}
	}
}

// 3.21 Implement the MT19937 Mersenne Twister RNG
func TestProblemTwentyOne(t *testing.T) {
	mt := rand.NewMersenneTwister()
	mt.Initialize(2)

	// values taken from https://create.stephan-brumme.com/mersenne-twister/
	first := int32(1872583848)
	second := int32(794921487)
	third := int32(111352301)
	fourth := int32(-294029752)

	if got := mt.Rand(); got != first {
		t.Fatalf("wanted %d, got %d", first, got)
	}

	if got := mt.Rand(); got != second {
		t.Fatalf("wanted %d, got %d", second, got)
	}

	if got := mt.Rand(); got != third {
		t.Fatalf("wanted %d, got %d", third, got)
	}

	if got := mt.Rand(); got != fourth {
		t.Fatalf("wanted %d, got %d", fourth, got)
	}
}

// 3.22 Crack an MT19937 seed
func TestProblemTwentyTwo(t *testing.T) {
	timestamp := uint32(time.Now().Unix())
	seed := timestamp + uint32(math_rand.Intn(1000))

	mt := rand.NewMersenneTwister()
	mt.Initialize(seed)

	sample := mt.Rand()

	test_mt := rand.NewMersenneTwister()
	guess := uint32(0)

	for i := timestamp; i < timestamp+1000; i++ {
		test_mt.Initialize(i)
		if candidate := test_mt.Rand(); sample == candidate {
			guess = i
			break
		}
	}

	if guess != seed {
		t.Errorf("wanted: %d, got: %d", seed, guess)
	}
}

// 3.23 Clone an MT19937 RNG from its output
func TestProblemTwentyThree(t *testing.T) {
	var clonedState [624]uint32

	mt := rand.NewMersenneTwister()
	mt.Initialize(uint32(math_rand.Intn(1000)))

	for i := 0; i < len(clonedState); i++ {
		clonedState[i] = untemperMT(uint32(mt.Rand()))
	}

	mtClone := rand.NewMersenneTwister()
	mtClone.LoadState(clonedState)

	for i := 0; i < 1000; i++ {
		want := mt.Rand()
		got := mtClone.Rand()

		if got != want {
			t.Fatal("Cloned output did not match expected")
		}
	}
}
