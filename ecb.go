package encrypt

import (
	"crypto/cipher"
)

type ecb struct {
	b         cipher.Block
	blockSize int
	tmp       []byte
}

func newEcb(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
		tmp:       make([]byte, b.BlockSize()),
	}
}

type ecbEncrypter ecb

func newECBEncrypter(key cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newEcb(key))
}

func (e *ecbEncrypter) BlockSize() int {
	return e.blockSize
}

func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		e.b.Encrypt(dst, src[:e.blockSize])
		dst, src = dst[e.blockSize:], src[e.blockSize:]
	}
}

type ecbDecrypter ecb

func newECBDecrypter(key cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newEcb(key))
}

func (e *ecbDecrypter) BlockSize() int {
	return e.blockSize
}

func (e *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		size := e.blockSize
		e.b.Decrypt(dst, src[:size])
		dst, src = dst[size:], src[size:]
	}
}
