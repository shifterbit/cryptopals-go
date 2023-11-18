package main

import (
	"fmt"
	"os"

	cryptopalsgo "github.com/shifterbit/cryptopals-go"
)

var defaultCharset []byte = []byte{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	' ',
}


func main() {
	if len(os.Args) < 2 {
		fmt.Println(os.Args[0], "[filename]")
		return
	}
	filename := os.Args[1]
	
	t, err := cryptopalsgo.CharacterFrequencyFromFile(filename, defaultCharset)
	if err != nil {
		fmt.Println(err)
	}
	


	prettyFreq := make(map[string]float64)
	for k, v := range t {
		prettyFreq[string(k)] = v
	}

	fmt.Printf("%#v\n", prettyFreq)
}
