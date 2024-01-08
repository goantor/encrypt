package encrypt

import "errors"

// Sha1Prng keyBytes aesKey encryptLength: 128/256
func Sha1Prng(keyBytes []byte, encryptLength int) ([]byte, error) {
	hashed := Sha1(Sha1(keyBytes))
	maxLen := len(hashed)
	realLen := encryptLength / 8
	if realLen > maxLen {
		return nil, errors.New("invalid length")
	}

	return hashed[0:realLen], nil
}
