package encrypt

import (
	"crypto/aes"
	"crypto/des"
)

func NewAes(key, iv []byte) IMethod {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return NewMethod(block, iv)
}

func NewDes(key, iv []byte) IMethod {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return NewMethod(block, iv)
}

func NewTripleDes(key, iv []byte) IMethod {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	return NewMethod(block, iv)
}
