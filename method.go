package encrypt

import "crypto/cipher"

type IMethod interface {
	ECB() IEncrypt
	CBC() IEncrypt
	CTR() IEncrypt
	OFB() IEncrypt
	CFB() IEncrypt
}

type Method struct {
	Base
}

func NewMethod(block cipher.Block, iv []byte) *Method {
	return &Method{Base: Base{
		block: block,
		iv:    iv,
	}}
}

func (m *Method) ECB() IEncrypt {
	m.encryptor = newEcbEncryptor(m.block)
	return m
}

func (m *Method) CBC() IEncrypt {
	m.checkIv()
	m.encryptor = newCbcEncryptor(m.block, m.iv)
	return m
}

func (m *Method) CTR() IEncrypt {
	m.checkIv()
	m.encryptor = newCtrEncryptor(m.block, m.iv)
	return m
}

func (m *Method) OFB() IEncrypt {
	m.checkIv()
	m.encryptor = newOfbEncryptor(m.block, m.iv)
	return m
}

func (m *Method) CFB() IEncrypt {
	m.checkIv()
	m.encryptor = newCfbEncryptor(m.block, m.iv)
	return m
}

func (m *Method) checkIv() {
	if m.iv == nil {
		panic("iv is nil")
	}
}
