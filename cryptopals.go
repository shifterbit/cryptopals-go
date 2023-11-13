package cryptopalsgo

import (
	"encoding/base64"
	"encoding/hex"
)

func Hex2Base64(b []byte) ([]byte, error) {
	decodedHex := make([]byte, len(b))
	_, err := hex.Decode(decodedHex, b)
	if err != nil {
		return nil, err
	}
	res := make([]byte, len(b))
	base64.RawStdEncoding.Decode(res, decodedHex)
	return res, nil
}
