package cryptopalsgo

import (
	"encoding/base64"
	"encoding/hex"
)

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
