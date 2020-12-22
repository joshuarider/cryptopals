package main

import (
	"fmt"
	"testing"
)

// 3.17 The CBC padding oracle
func TestProblemSeventeen(t *testing.T) {
	ciphertext, cipher, iv := encryptForCBCOracle()
	fmt.Println(string(CBCPaddingOracle(ciphertext, cipher, iv)))
}
