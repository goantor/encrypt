package encrypt

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type IWrap interface {
	Encode([]byte) []byte
	Decode([]byte) ([]byte, error)
}

type Base64SafeWrap struct {
}

func (b Base64SafeWrap) Encode(bytes []byte) (dst []byte) {
	dst = make([]byte, base64.StdEncoding.EncodedLen(len(bytes)))
	base64.StdEncoding.Encode(dst, bytes)
	str := string(dst)
	str = strings.Replace(str, "+", "-", -1)
	str = strings.Replace(str, "/", "_", -1)
	dst = []byte(str)
	return
}

func (b Base64SafeWrap) Decode(bytes []byte) (dst []byte, err error) {
	var index int
	str := string(bytes)
	str = strings.Replace(str, "-", "+", -1)
	str = strings.Replace(str, "_", "/", -1)
	mod4 := len(str) % 4
	if mod4 != 0 {
		str = str + "===="[0:mod4]
	}

	bs := []byte(str)
	dst = make([]byte, base64.StdEncoding.EncodedLen(len(bs)))
	if index, err = base64.StdEncoding.Decode(dst, bs); err != nil {
		return
	}

	return dst[:index], nil
}

type Base64Wrap struct {
}

func (b Base64Wrap) Encode(bytes []byte) (dst []byte) {
	dst = make([]byte, base64.StdEncoding.EncodedLen(len(bytes)))
	base64.StdEncoding.Encode(dst, bytes)
	return
}

func (b Base64Wrap) Decode(bytes []byte) (dst []byte, err error) {
	var index int
	dst = make([]byte, base64.StdEncoding.EncodedLen(len(bytes)))
	if index, err = base64.StdEncoding.Decode(dst, bytes); err != nil {
		return
	}

	return dst[:index], nil
}

type HexWrap struct {
}

func (h HexWrap) Encode(bytes []byte) (dst []byte) {
	dst = make([]byte, hex.EncodedLen(len(bytes)))
	index := hex.Encode(dst, bytes)
	return dst[:index]
}

func (h HexWrap) Decode(bytes []byte) (dst []byte, err error) {
	var index int
	dst = make([]byte, hex.DecodedLen(len(bytes)))
	if index, err = hex.Decode(dst, bytes); err != nil {
		return
	}

	return dst[:index], nil
}
