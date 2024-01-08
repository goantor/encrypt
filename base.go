package encrypt

import (
	"crypto/cipher"
	"errors"
)

type Bytes struct {
	data interface{}
}

func NewBytes(data interface{}) *Bytes {
	return &Bytes{data: data}
}

func (b Bytes) Original() (original []byte) {
	original, _ = b.data.([]byte)
	return
}

func (b Bytes) String() string {
	str, _ := b.data.(string)
	return str
}

type method int

const (
	ebc method = iota
	cbc
	ctr
	ofb
	cfb
)

var (
	ErrPaddingSize = errors.New("padding size invalid")
	ErrKeyLength   = errors.New("key length invalid")

	base64Wrap     = &Base64Wrap{}
	base64SafeWrap = &Base64SafeWrap{}
	hexWrap        = &HexWrap{}

	noPadding    = &NoPadding{}
	pkcs7Padding = &Pkcs7Padding{}
	zeroPadding  = &ZeroPadding{}
)

type IPaddingType interface {
	NoPadding() IEncrypt
	ZeroPadding() IEncrypt
	Pkcs5Padding() IEncrypt
	Pkcs7Padding() IEncrypt
}

type IWrapType interface {
	Base64Safe() IEncrypt
	Base64() IEncrypt
	Hex() IEncrypt
}

type IEncrypt interface {
	IPaddingType
	IWrapType
	IEncryptor
	//Encrypt([]byte) []byte
	//Decrypt([]byte) ([]byte, error)
}

type IEncryptor interface {
	Encrypt(src []byte) (dst []byte)
	Decrypt(src []byte) (dst []byte, err error)
}

type Base struct {
	block     cipher.Block
	iv        []byte
	text      Text
	padding   IPadding
	wrap      IWrap
	encryptor IEncryptor
}

func (a *Base) Encrypt(text []byte) []byte {
	plainText := a.fill(text)
	return a.encode(
		a.encryptor.Encrypt(plainText),
	)
}

func (a *Base) Decrypt(bytes []byte) (dst []byte, err error) {
	var src []byte
	if src, err = a.decode(bytes); err != nil {
		return
	}

	var decrypted []byte
	if decrypted, err = a.encryptor.Decrypt(src); err != nil {
		return
	}

	return a.restore(decrypted), nil
}

//func NewMethod(block cipher.Block, iv []byte) *Base {
//	return &Base{
//		block: block,
//	}
//}

func (a *Base) NoPadding() IEncrypt {
	a.padding = noPadding
	return a
}

func (a *Base) ZeroPadding() IEncrypt {
	a.padding = zeroPadding
	return a
}

func (a *Base) Pkcs5Padding() IEncrypt {
	// pkcs7 向下兼容pkcs5Padding
	a.padding = pkcs7Padding
	return a
}

func (a *Base) Pkcs7Padding() IEncrypt {
	a.padding = pkcs7Padding
	return a
}

func (a *Base) Base64Safe() IEncrypt {
	a.wrap = base64SafeWrap
	return a
}

func (a *Base) Base64() IEncrypt {
	a.wrap = base64Wrap
	return a
}

func (a *Base) Hex() IEncrypt {
	a.wrap = hexWrap
	return a
}

func (a *Base) fill(text []byte) []byte {
	if a.padding == nil {
		return text
	}

	return a.padding.Fill(text, a.block.BlockSize())
}

func (a *Base) restore(text []byte) []byte {
	if a.padding == nil {
		return text
	}

	return a.padding.Restore(text, a.block.BlockSize())
}

func (a *Base) encode(crypto []byte) []byte {
	if a.wrap == nil {
		return crypto
	}

	return a.wrap.Encode(crypto)
}

func (a *Base) decode(crypto []byte) ([]byte, error) {
	if a.wrap == nil {
		return crypto, nil
	}

	return a.wrap.Decode(crypto)
}
