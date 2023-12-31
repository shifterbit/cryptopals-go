package cryptopalsgo_test

import (
	"bytes"
	"encoding/hex"
	"os"
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

func TestRecoverSingleByteXor(t *testing.T) {

	input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := []byte("Cooking MC's like a pound of bacon")
	expectedKey := 'X'
	key, plaintext := cryptopalsgo.RecoverSingleByteXOR(input)
	if bytes.Equal(expected, plaintext) != true || key != byte(expectedKey) {
		t.Fatalf("expected plaintext %q got %q \n expected key %q got %q",
			string(expected), string(plaintext), string(expectedKey), string(key))
	}

}

func TestDetectSingleByteXOR(t *testing.T) {
	input, _ := os.ReadFile("4.txt")
	splitInput := bytes.Split(input, []byte{'\n'})
	hexDecodedInput := cryptopalsgo.HexDecodeAll(splitInput)

	expected := []byte("Now that the party is jumping\n")
	expectedKey := '5'
	key, plaintext := cryptopalsgo.DetectSingleByteXOR(hexDecodedInput)
	if bytes.Equal(expected, plaintext) != true || key != byte(expectedKey) {
		t.Fatalf("expected plaintext %q got %q \n expected key %q got %q",
			string(expected), string(plaintext), string(expectedKey), string(key))
	}
}

func TestRepeatingKeyXOR(t *testing.T) {

	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	expected := []byte("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	ciphertext := cryptopalsgo.RepeatingKeyXOR([]byte("ICE"), input)
	encoded := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(encoded, ciphertext)
	if !bytes.Equal(expected, encoded) {
		t.Fatalf("expected %q got %q",
			string(expected), string(encoded))
	}
}

func TestHammingDistance(t *testing.T) {
	input := []byte("this is a test")
	input2 := []byte("wokka wokka!!!")
	expected := 37
	output, _ := cryptopalsgo.HammingDistance(input, input2)
	if  output != expected {
		t.Fatalf("expected %v got %v", expected, output)
	}

}