package encrypt

import (
	"crypto/cipher"
)

type ecbEncryptor struct {
	block cipher.Block
}

func newEcbEncryptor(b cipher.Block) *ecbEncryptor {
	return &ecbEncryptor{block: b}
}

func (a ecbEncryptor) Encrypt(plainText []byte) (dst []byte) {
	crypto := make([]byte, len(plainText))
	blockMode := newECBEncrypter(a.block)
	blockMode.CryptBlocks(crypto, plainText)
	return crypto
}

func (a ecbEncryptor) Decrypt(src []byte) (dst []byte, err error) {
	text := make([]byte, len(src))
	blockMode := newECBDecrypter(a.block)
	blockMode.CryptBlocks(text, src)
	return text, nil
}

type cbcEncryptor struct {
	block cipher.Block
	iv    []byte
}

func newCbcEncryptor(block cipher.Block, iv []byte) *cbcEncryptor {
	return &cbcEncryptor{block: block, iv: iv}
}

func (c cbcEncryptor) Encrypt(src []byte) (dst []byte) {
	crypto := make([]byte, len(src))
	blockMode := cipher.NewCBCEncrypter(c.block, c.iv)
	blockMode.CryptBlocks(crypto, src)
	return crypto
}

func (c cbcEncryptor) Decrypt(src []byte) (dst []byte, err error) {
	var text = make([]byte, len(src))
	blockMode := cipher.NewCBCDecrypter(c.block, c.iv)
	blockMode.CryptBlocks(text, src)
	return text, nil
}

type ctrEncryptor struct {
	block cipher.Block
	iv    []byte
}

func newCtrEncryptor(block cipher.Block, iv []byte) *ctrEncryptor {
	return &ctrEncryptor{block: block, iv: iv}
}

func (c ctrEncryptor) Encrypt(src []byte) (dst []byte) {
	crypto := make([]byte, len(src))
	stream := cipher.NewCTR(c.block, c.iv)
	stream.XORKeyStream(crypto, src)
	return crypto
}

func (c ctrEncryptor) Decrypt(src []byte) (dst []byte, err error) {
	//TODO implement me
	var text = make([]byte, len(src))
	stream := cipher.NewCTR(c.block, c.iv)
	stream.XORKeyStream(text, src)
	return text, nil
}

type ofbEncryptor struct {
	block cipher.Block
	iv    []byte
}

func newOfbEncryptor(block cipher.Block, iv []byte) *ofbEncryptor {
	return &ofbEncryptor{block: block, iv: iv}
}

func (o ofbEncryptor) Encrypt(src []byte) (dst []byte) {
	crypto := make([]byte, len(src))
	stream := cipher.NewOFB(o.block, o.iv)
	stream.XORKeyStream(crypto, src)
	return crypto
}

func (o ofbEncryptor) Decrypt(src []byte) (dst []byte, err error) {
	var text = make([]byte, len(src))
	stream := cipher.NewOFB(o.block, o.iv)
	stream.XORKeyStream(text, src)
	return text, nil
}

type cfbEncryptor struct {
	block cipher.Block
	iv    []byte
}

func newCfbEncryptor(block cipher.Block, iv []byte) *cfbEncryptor {
	return &cfbEncryptor{block: block, iv: iv}
}

func (c cfbEncryptor) Encrypt(src []byte) (dst []byte) {
	crypto := make([]byte, len(src))
	stream := cipher.NewCFBEncrypter(c.block, c.iv)
	stream.XORKeyStream(crypto, src)
	return crypto
}

func (c cfbEncryptor) Decrypt(src []byte) (dst []byte, err error) {
	var text = make([]byte, len(src))
	stream := cipher.NewCFBDecrypter(c.block, c.iv)
	stream.XORKeyStream(text, src)
	return text, nil
}
