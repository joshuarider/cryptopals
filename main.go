package main

func main() {
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
