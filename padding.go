package encrypt

import (
	"bytes"
)

type IPadding interface {
	Fill(src []byte, blockSize int) []byte
	Restore(src []byte, blockSize int) []byte
}

type Padding struct {
}

type NoPadding struct {
}

func (n NoPadding) Fill(src []byte, blockSize int) []byte {
	times := blockSize - len(src)%blockSize
	return append(src, bytes.Repeat([]byte{byte(0)}, times)...)
}

func (n NoPadding) Restore(src []byte, blockSize int) []byte {
	size, zero := len(src)-1, byte(0)
	for ; size > 0; size-- {
		if src[size] != zero {
			break
		}
	}

	return src[:size+1]
}

type ZeroPadding struct {
}

func (z ZeroPadding) Fill(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := make([]byte, len(src)+padding)
	copy(padText, src)
	return padText
}

func (z ZeroPadding) Restore(src []byte, blockSize int) []byte {
	// Find the last non-zero byte
	for i := len(src) - 1; i >= 0; i-- {
		if src[i] != 0 {
			return src[:i+1]
		}
	}
	return nil
}

type Pkcs7Padding struct {
}

func (p Pkcs7Padding) Fill(src []byte, blockSize int) []byte {
	surplus := len(src) % blockSize
	if surplus == 0 {
		return src
	}

	times := blockSize - surplus
	return append(src, bytes.Repeat([]byte{byte(times)}, times)...)
}

func (p Pkcs7Padding) Restore(src []byte, blockSize int) []byte {
	length := len(src)
	max := length - int(src[length-1])
	return src[:max]
}

type Pkcs5Padding struct {
	Pkcs7Padding
}
