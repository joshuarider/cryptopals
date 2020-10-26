package main

type ScoreResult struct {
	Score float64
	Line  []byte
}

type ScoreResults []ScoreResult

func (r ScoreResults) Len() int {
	return len(r)
}

func (r ScoreResults) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r ScoreResults) Less(i, j int) bool {
	return r[i].Score > r[j].Score
}

func (r *ScoreResults) Push(x interface{}) {
	*r = append(*r, x.(ScoreResult))
}

func (r *ScoreResults) Pop() interface{} {
	old := *r
	n := len(old)
	x := old[n-1]
	*r = old[0 : n-1]
	return x
}

func main() {
	// 1.1
	//	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	//	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	//	got := encoding.BytesToB64(encoding.HexToBytes(in))
	//
	//	fmt.Println(expected == got)

	// 1.2
	//	in1 := "1c0111001f010100061a024b53535009181c"
	//	in2 := "686974207468652062756c6c277320657965"
	//	expected := "746865206b696420646f6e277420706c6179"
	//
	//	got := encoding.XorHex(in1, in2)
	//	fmt.Printf("want: %s, got %s, match: %v", expected, got, got == expected)

	// 1.3
	//	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	//	raw := encoding.HexToBytes(in)
	//	hits := make(map[uint8]float64)
	//
	//	for i := uint8(1); i <= uint8(200); i++ {
	//		candidate := encoding.XorSingleByte(raw, i)
	//		hits[i] = cracker.Score(candidate)
	//	}
	//
	//	for k, v := range hits {
	//		if v < 0.0 {
	//			continue
	//		}
	//		candidate := encoding.XorSingleByte(raw, k)
	//		fmt.Println(string(candidate))
	//	}

	// 1.4
	//	if len(os.Args) != 2 {
	//		fmt.Println("need input file")
	//		os.Exit(1)
	//	}
	//
	//	file, err := os.Open(os.Args[1])
	//	if err != nil {
	//		os.Exit(1)
	//	}
	//	defer file.Close()
	//
	//	scanner := bufio.NewScanner(file)
	//	hits := make(ScoreResults, 1)
	//
	//	for scanner.Scan() {
	//		for i := uint8(0); i < uint8(255); i++ {
	//			hex := string(scanner.Bytes())
	//			raw := encoding.HexToBytes(hex)
	//
	//			candidate := encoding.XorSingleByte(raw, i)
	//			score := cracker.Score(candidate)
	//			hits = append(hits, ScoreResult{Score: score, Line: candidate})
	//		}
	//	}
	//
	//	sort.Sort(hits)
	//
	//	fmt.Printf("%v\n", string(hits[0].Line))

	// 1.5
	// expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	//	in := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	//
	//	out := encoding.RepeatedKeyXor(in, []byte("ICE"))
	//	hexOut := encoding.BytesToHex(out)
	//	fmt.Println(hexOut)
	//	fmt.Println(expected == hexOut)

	// 1.6
	//	test1 := []byte("wokka wokka!!!")
	//	test2 := []byte("this is a test")
	//
	//	fmt.Println(37 == cracker.HammingDistance(test1, test2))
	//	if len(os.Args) != 2 {
	//		fmt.Println("need input file")
	//		os.Exit(1)
	//	}
	//
	//	file, err := os.Open(os.Args[1])
	//	if err != nil {
	//		fmt.Printf("%s does not exist\n", os.Args[1])
	//		os.Exit(1)
	//	}
	//	defer file.Close()
	//
	//	b64 := ""
	//	sc := bufio.NewScanner(file)
	//
	//	for sc.Scan() {
	//		b64 += sc.Text()
	//	}
	//
	//	bytes, err := encoding.B64ToBytes(string(b64))
	//	if err != nil {
	//		fmt.Printf("something blew up: %v", err)
	//		os.Exit(1)
	//	}
	//
	//	keyLength := cracker.GuessRepeatedXorKeyLength(bytes)
	//
	//	transpositions := cracker.Transpose(bytes, keyLength)
	//
	//	key := make([]byte, keyLength)
	//	for t := range transpositions {
	//		key[t] = cracker.BestGuess(transpositions[t])
	//	}
	//	fmt.Println(string(key))
	//	fmt.Printf("---\n %s \n---\n", encoding.RepeatedKeyXor(bytes, key))

	// 1.7

	//	if len(os.Args) != 2 {
	//		fmt.Println("must specify input file")
	//		os.Exit(1)
	//	}
	//
	//	file, err := os.Open(os.Args[1])
	//	if err != nil {
	//		fmt.Printf("error opening file: %s\n", os.Args[1])
	//		os.Exit(1)
	//	}
	//
	//	b64Text := ""
	//
	//	s := bufio.NewScanner(file)
	//
	//	for s.Scan() {
	//		b64Text += s.Text()
	//	}
	//
	//	cipherBytes, err := encoding.B64ToBytes(b64Text)
	//	if err != nil {
	//		fmt.Printf("error decoding b64: %v\n", err)
	//		os.Exit(1)
	//	}
	//
	//	decrypted := crypto.ECBDecryptAES(cipherBytes, []byte("YELLOW SUBMARINE"))
	//
	//	fmt.Println(string(decrypted))

	// 1.8
	//	if len(os.Args) != 2 {
	//		fmt.Println("must specify input file")
	//		os.Exit(1)
	//	}
	//
	//	file, err := os.Open(os.Args[1])
	//	if err != nil {
	//		fmt.Printf("error opening file: %s\n", os.Args[1])
	//		os.Exit(1)
	//	}
	//
	//	s := bufio.NewScanner(file)
	//	blockSize := 32
	//
	//	for s.Scan() {
	//		cipherText := s.Text()
	//		blocks := make(map[string]struct{})
	//
	//		for i := 0; i+blockSize < len(cipherText); i = i + blockSize {
	//			chunk := cipherText[i : i+blockSize]
	//			if _, ok := blocks[chunk]; ok {
	//				fmt.Printf("duplicate block found in: %s\n", cipherText)
	//				continue
	//			}
	//
	//			blocks[chunk] = struct{}{}
	//		}
	//	}

	// 2.9

	//	testSubmarine := []byte("YELLOW SUBMARINE")
	//	for i := 10; i < 22; i++ {
	//		fmt.Printf("Block size: %d, %q\n", i, crypto.PKCSPad(testSubmarine, i))
	//	}

	//	fmt.Println(crypto.PKCSUnpad([]byte("\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f")))
	//	fmt.Println(crypto.PKCSUnpad([]byte("\x01")))
	//	fmt.Println(crypto.PKCSUnpad([]byte("\x02\x02")))

	// 2.10
	// "input/2/10.txt"
	//if len(os.Args) != 2 {
	//	fmt.Println("must specify input file")
	//	os.Exit(1)
	//}

	//file, err := os.Open(os.Args[1])
	//if err != nil {
	//	fmt.Printf("error opening file: %s\n", os.Args[1])
	//	os.Exit(1)
	//}

	//b64Text := ""

	//s := bufio.NewScanner(file)

	//for s.Scan() {
	//	b64Text += s.Text()
	//}

	//cipherBytes, err := encoding.B64ToBytes(b64Text)
	//if err != nil {
	//	fmt.Printf("error decoding b64: %v\n", err)
	//	os.Exit(1)
	//}

	//key := []byte("YELLOW SUBMARINE")
	//iv := make([]byte, 16)

	//fmt.Printf("%s\n", crypto.CBCDecryptAES(cipherBytes, key, iv))

	// 2.11
	//crypter := mysteryEncrypter()
	//fmt.Println("Prediction:", cipherOracle(crypter))
}
