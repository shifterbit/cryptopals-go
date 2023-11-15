package cryptopalsgo_test

import (
	"bytes"
	"testing"

	cryptopalsgo "github.com/shifterbit/cryptopals-go"
)

func TestHex2Base64(t *testing.T) {
	input := []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	expected := []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
	output, err := cryptopalsgo.Hex2Base64(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(expected, output) != true {
		t.Fatalf("expected %q got %q", string(expected), string(output))
	}


}
