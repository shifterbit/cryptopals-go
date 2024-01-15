package cryptopalsgo

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"os"

	editdistance "github.com/shifterbit/cryptopals-go/editdistance"
)

type charFrequencyTable map[byte]uint
type relativeCharFrequencyTable map[byte]float64

var defaultCharset []byte = []byte{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	' ',
}

var defaultFreq relativeCharFrequencyTable = map[byte]float64{
	' ': 0.18622573464368689,
	'a': 0.06687857844137918,
	'b': 0.011429626821420586,
	'c': 0.01979916985020365,
	'd': 0.03562256374364508,
	'e': 0.10265861790751704,
	'f': 0.01706181408144022,
	'g': 0.015020462123200452,
	'h': 0.054029725972801416,
	'i': 0.051265152177928125,
	'j': 0.0006648974949695256,
	'k': 0.006744238041079778,
	'l': 0.03281716290960699,
	'm': 0.021486687469015192,
	'n': 0.055110670438307426,
	'o': 0.06446395069648984,
	'p': 0.01283524345552283,
	'q': 0.0007834903230196456,
	'r': 0.04726215819505604,
	's': 0.05129625849348225,
	't': 0.07364031378495815,
	'u': 0.025100852507460657,
	'v': 0.008497856580443849,
	'w': 0.02044851418739611,
	'x': 0.0010537264393961486,
	'y': 0.017458419604755377,
	'z': 0.00034411361581756144}

func Hex2Base64(b []byte) ([]byte, error) {
	decodedHex := make([]byte, hex.DecodedLen(len(b)))
	_, err := hex.Decode(decodedHex, b)
	if err != nil {
		return nil, err
	}
	res := make([]byte, base64.RawStdEncoding.EncodedLen(len(decodedHex)))
	base64.RawStdEncoding.Encode(res, decodedHex)
	return res, nil
}

func FixedXOR(key []byte, b []byte) []byte {
	res := make([]byte, len(b))
	for i, v := range b {
		res[i] = key[i] ^ v
	}
	return res
}

func SingleByteXOR(key byte, b []byte) []byte {
	expandedKey := bytes.Repeat([]byte{key}, len(b))
	return FixedXOR(expandedKey, b)
}

func RepeatingKeyXOR(key []byte, b []byte) []byte {
	minRepetitions := 1 + len(b)/len(key)
	repeatedKey := bytes.Repeat(key, minRepetitions)
	repeatedKey = repeatedKey[:len(b)]
	return FixedXOR(repeatedKey, b)
}

func RecoverSingleByteXOR(b []byte) (byte, []byte) {
	possiblePlaintexts := bruteforceSingleByteXOR(b)
	var bestKey byte = ' '
	var bestPlaintext []byte = nil
	var lowestScore float64 = math.Inf(1)
	for key, plaintext := range possiblePlaintexts {
		score := englishness(plaintext)
		if lowestScore > score && percentFromCharset(defaultCharset, plaintext) > 70 {
			lowestScore = score
			bestKey = key
			bestPlaintext = plaintext
		}
	}
	return bestKey, bestPlaintext
}

func DetectSingleByteXOR(b [][]byte) (byte, []byte) {
	type plaintextKeyPair struct {
		key       byte
		plaintext []byte
	}
	var pairs []plaintextKeyPair = make([]plaintextKeyPair, 0)
	for _, value := range b {
		key, plaintext := RecoverSingleByteXOR(value)
		pairs = append(pairs, plaintextKeyPair{
			key:       key,
			plaintext: plaintext,
		})
	}
	var bestPair plaintextKeyPair
	var lowestScore float64 = math.Inf(1)
	for _, value := range pairs {
		score := englishness(value.plaintext)
		if lowestScore > score {
			lowestScore = score
			bestPair = value
		}
	}

	return bestPair.key, bestPair.plaintext

}

// BreakRepeatingKeyXOR ...
func BreakRepeatingKeyXOR(b []byte) ([]byte, error) {

	keySizeDistances := []editdistance.KeysizeEditDistance{}
	for keySize := 2; keySize < 40; keySize++ {
		chunked := chunkBytes(b, keySize)

		distance1, err := HammingDistance(chunked[0], chunked[1])
		distance2, err := HammingDistance(chunked[2], chunked[3])
		averageDistance := (distance1 + distance2) / 2
		normalized := averageDistance / keySize
		keySizeDistances = append(keySizeDistances, editdistance.KeysizeEditDistance{
			KeySize:      keySize,
			EditDistance: normalized,
		})

		if err != nil {
			return nil, err
		}
	}

	editdistance.By(editdistance.ByDistance).Sort(keySizeDistances)
	keySize := keySizeDistances[0].KeySize
	blocks := chunkBytes(b, keySize)
	transposedBlocks := transposeBlocks(blocks)

	key := []byte{}
	for _, block := range transposedBlocks {
		blockKey, _ := RecoverSingleByteXOR(block)
		key = append(key, blockKey)
	}
	return key, nil
}

func DecryptAesECB(key []byte, ciphertext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := 16
	plaintext := make([]byte, len(ciphertext))
	for start, end := 0, size; start < len(ciphertext); start, end = start+size, end+size {
		cipher.Decrypt(plaintext[start:end], ciphertext[start:end])
	}

	cipher.Decrypt(plaintext, ciphertext)
	return plaintext, nil
}

func DetectAesECB(ciphertexts [][]byte) []byte {
	for _, ciphertext := range ciphertexts {
		if hasMatchingChunks(ciphertext, 16) {
			return ciphertext
		}
	}
	return nil
}
func hasMatchingChunks(b []byte, chunkSize int) bool {
	chunked := chunkBytes(b, 16)
	duplicates := make(map[([16]byte)]bool)
	for _, chunk := range chunked {
		val, ok := duplicates[[16]byte(chunk)]

		if !ok {
			duplicates[[16]byte(chunk)] = false
			continue
		}

		if val == false {
			return true
		}
	}
	return false
}

func transposeBlocks(blocks [][]byte) [][]byte {
	transposed := make([][]byte, len(blocks[0]))

	for _, block := range blocks {
		for pos, val := range block {
			transposed[pos] = append(transposed[pos], val)
		}
	}

	return transposed
}

func chunkBytes(b []byte, size int) [][]byte {
	curr := b
	chunks := [][]byte{}
	for len(curr) > 0 {
		if len(curr) < size {
			chunks = append(chunks, curr)
			curr = []byte{}
			continue
		}
		chunks = append(chunks, curr[:size])
		curr = curr[size:]
	}
	return chunks
}

func percentFromCharset(charset []byte, b []byte) int {
	count := float64(0)
	total := float64(len(b))
	for _, v := range b {
		if bytes.Contains(charset, []byte{v}) {
			count = count + 1
		}

	}

	return int(math.Round(count * 100 / total))
}

func bruteforceSingleByteXOR(b []byte) map[byte]([]byte) {
	var keys []byte
	for i := 0; i < 255; i++ {
		keys = append(keys, byte(i))
	}

	var outputs map[byte][](byte) = make(map[byte]([]byte))
	for _, v := range keys {
		outputs[v] = SingleByteXOR(v, b)
	}

	return outputs
}

func byteFrequency(charset []byte, b []byte) charFrequencyTable {
	var freq charFrequencyTable = nil
	for _, v := range b {
		if bytes.Contains(charset, []byte{v}) {
			if freq == nil {
				freq = make(charFrequencyTable)
			}
			freq[v] += 1
		}
	}
	return freq
}

func relativeByteFrequency(freq charFrequencyTable) relativeCharFrequencyTable {
	if freq == nil {
		return nil
	}

	total_count := uint(0)
	for _, v := range freq {
		total_count += v
	}

	relativeFreqs := make(relativeCharFrequencyTable)
	for k, v := range freq {
		relativeFreqs[k] = float64(float64(v) / float64(total_count))
	}

	return relativeFreqs
}
func expandRelativeCharFreq(freq relativeCharFrequencyTable, length int) charFrequencyTable {
	freqs := make(charFrequencyTable)
	for char, relativeFreq := range freq {
		freqs[char] = uint(math.Round(relativeFreq * float64(length)))
	}
	return freqs
}

func CharacterFrequencyFromFile(filename string, charset []byte) (relativeCharFrequencyTable, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	freq := byteFrequency(charset, b)
	relativeFreq := relativeByteFrequency(freq)
	return relativeFreq, nil

}

func HexDecodeAll(b [][]byte) [][]byte {
	outputs := make([][]byte, 0)
	for i := range b {
		decoded := make([]byte, hex.DecodedLen(len(b[i])))
		hex.Decode(decoded, b[i])
		outputs = append(outputs, decoded)
	}
	return outputs
}

func chiSqr(expectedDist charFrequencyTable, observedDist charFrequencyTable) float64 {

	score := float64(0)
	for k, v := range expectedDist {
		score += math.Pow((float64(observedDist[k])-float64(v)), 2) / float64(v)
	}
	return score
}

func englishness(b []byte) float64 {
	freqb := byteFrequency(defaultCharset, b)
	freq := relativeByteFrequency(freqb)

	if freqb == nil {
		return math.Inf(1)
	}
	expandedDefaultFreq := expandRelativeCharFreq(defaultFreq, 1000000)
	expandedFreq := expandRelativeCharFreq(freq, 1000000)
	return chiSqr(expandedDefaultFreq, expandedFreq)
}

func HammingDistance(a []byte, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("Must be of same lenth")
	}
	distance := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			fst := int(a[i])
			snd := int(b[i])
			xor := fst ^ snd
			for int(xor) != 0 {
				xor = xor & (xor - 1)
				distance++
			}
		}
	}
	return distance, nil
}
