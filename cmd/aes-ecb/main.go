package main

import (
	"encoding/base64"
	"fmt"
	"os"

	cryptopalsgo "github.com/shifterbit/cryptopals-go"
)

func main() {
	bs, err := os.ReadFile("7.txt")
	if err != nil {
		fmt.Errorf("Error Reading file")
	}

	encrypted := make([]byte, base64.RawStdEncoding.DecodedLen(len(bs)))
	base64.StdEncoding.Decode(encrypted, bs)

	plaintext, err := cryptopalsgo.DecryptAesECB([]byte("YELLOW SUBMARINE"), encrypted)
	fmt.Println(string(plaintext))
	
}