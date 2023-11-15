package cryptopalsgo_test

import (
	"bytes"
	"encoding/hex"
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

func TestFixedXOR(t *testing.T) {
	input := []byte("1c0111001f010100061a024b53535009181c")
	key := []byte("686974207468652062756c6c277320657965")
	expected := []byte("746865206b696420646f6e277420706c6179")

	decodedInput := make([]byte, hex.DecodedLen(len(input)))
	decodedKey := make([]byte, hex.DecodedLen(len(key)))
	decodedExpected := make([]byte, hex.DecodedLen(len(expected)))
	_, err := hex.Decode(decodedInput, input)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hex.Decode(decodedKey, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = hex.Decode(decodedExpected, expected)
	if err != nil {
		t.Fatal(err)
	}

	output := cryptopalsgo.FixedXOR(decodedKey, decodedInput)

	if bytes.Equal(decodedExpected, output) != true {
		t.Fatalf("expected %q got %q", string(expected), string(output))
	}
}

