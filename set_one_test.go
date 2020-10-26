package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/joshuarider/cryptopals/cracker"
	"github.com/joshuarider/cryptopals/crypto"
	"github.com/joshuarider/cryptopals/encoding"
)

// 1.1 Convert hex to base64
func TestProblemOne(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	bytes, err := encoding.HexToBytes(in)
	if err != nil {
		t.Fatalf("Unexpected error encoding HexToBytes")
	}
	if got := encoding.BytesToB64(bytes); want != got {
		t.Errorf("want =  %s, got = %s", want, got)
	}
}

// 1.2 Fixed XOR
func TestProblemTwo(t *testing.T) {
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"
	want := "746865206b696420646f6e277420706c6179"

	if got := encoding.XorHex(in1, in2); want != got {
		t.Errorf("want= %s, got = %s", want, got)
	}
}

// 1.3 Single-byte XOR cipher
func TestProblemThree(t *testing.T) {
	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	want := "Cooking MC's like a pound of bacon"

	raw, err := encoding.HexToBytes(in)
	if err != nil {
		t.Fatalf("Error calling HexToBytes(%s)", in)
	}

	cleartext := encoding.XorSingleByte(raw, uint8(1))
	bestScore := cracker.Score(cleartext)

	for i := uint8(2); i <= uint8(200); i++ {
		candidate := encoding.XorSingleByte(raw, i)
		if s := cracker.Score(candidate); s > bestScore {
			bestScore = s
			cleartext = candidate
		}
	}

	if want != string(cleartext) {
		t.Errorf("Unexpected \"best\" cleartext: %s", string(cleartext))
	}
}

// 1.4 Detect single-character XOR
func TestProblemFour(t *testing.T) {
	inputFile := "input/1/4.txt"
	want := "Now that the party is jumping\n"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("Unable to open: %s, %v", inputFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	hits := make(ScoreResults, 1)

	for scanner.Scan() {
		for i := uint8(0); i < uint8(255); i++ {
			hex := string(scanner.Bytes())

			raw, err := encoding.HexToBytes(hex)
			if err != nil {
				continue
			}

			candidate := encoding.XorSingleByte(raw, i)
			score := cracker.Score(candidate)
			hits = append(hits, ScoreResult{Score: score, Line: candidate})
		}
	}

	if len(hits) < 1 {
		t.Fatalf("No valid possibilities found.")
	}

	sort.Sort(hits)
	got := string(hits[0].Line)

	if want != got {
		t.Errorf("want = %#v, got = %#v", want, got)
	}
}

// 1.5 Implement repeating-key XOR
func TestProblemFive(t *testing.T) {
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	in := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

	out := encoding.RepeatedKeyXor(in, []byte("ICE"))
	got := encoding.BytesToHex(out)

	if want != got {
		t.Errorf("got = %s, want = %s", got, want)
	}
}

// 1.6 Break repeating-key XOR
func TestProblemSix(t *testing.T) {
	pocWant := 37
	poc1 := []byte("wokka wokka!!!")
	poc2 := []byte("this is a test")

	if pocGot := cracker.HammingDistance(poc1, poc2); pocWant != pocGot {
		t.Fatalf("HammingDistance PoC failed, want = %d, got = %d", pocWant, pocGot)
	}

	inputFile := "input/1/6.txt"
	want := "Terminator X: Bring the noise"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("Unable to open %s, %v \n", inputFile, err)
	}
	defer file.Close()

	b64 := ""
	sc := bufio.NewScanner(file)

	for sc.Scan() {
		b64 += sc.Text()
	}

	bytes, err := encoding.B64ToBytes(string(b64))
	if err != nil {
		t.Fatalf("Error converting B64ToBytes: %v", err)
	}

	keyLength := cracker.GuessRepeatedXorKeyLength(bytes)

	transpositions := cracker.Transpose(bytes, keyLength)

	key := make([]byte, keyLength)
	for t := range transpositions {
		key[t] = cracker.BestGuess(transpositions[t])
	}
	if got := string(key); want != got {
		t.Errorf("want = %v, got = %v", want, got)
	}
}

// 1.7 AES in ECB mode
func TestProblemSeven(t *testing.T) {
	inputFile := "input/1/7.txt"
	want := `I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
`

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("Unable to open %s, %v \n", inputFile, err)
	}

	b64Text := ""

	s := bufio.NewScanner(file)

	for s.Scan() {
		b64Text += s.Text()
	}

	cipherBytes, err := encoding.B64ToBytes(b64Text)
	if err != nil {
		fmt.Printf("error decoding b64: %v\n", err)
		os.Exit(1)
	}

	decrypted := crypto.ECBDecryptAES(cipherBytes, []byte("YELLOW SUBMARINE"))
	if got := string(decrypted); want != got {
		t.Errorf("want = %#v, got = %#v", want, got)
	}
}

// 1.8 Detect AES in ECB mode
func TestProblemEight(t *testing.T) {
	inputFile := "input/1/8.txt"
	want := "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("Unable to open %s, %v \n", inputFile, err)
	}

	s := bufio.NewScanner(file)
	blockSize := 16
	ecbTexts := []string{}

	for s.Scan() {
		cipherText := s.Text()
		blocks := make(map[string]struct{})

		for i := 0; i+blockSize < len(cipherText); i = i + blockSize {
			chunk := cipherText[i : i+blockSize]
			if _, ok := blocks[chunk]; ok {
				ecbTexts = append(ecbTexts, cipherText)
				break
			}

			blocks[chunk] = struct{}{}
		}
	}

	if len(ecbTexts) != 1 {
		t.Fatalf("Expected 1, got %d", len(ecbTexts))
	}

	if got := ecbTexts[0]; want != got {
		t.Errorf("want = %s, got = %s", want, got)
	}
}
