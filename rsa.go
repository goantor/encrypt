package encrypt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

type RsaWay int

var (
	startPrefix = []byte("\n-----BEGIN ")
	endPrefix   = []byte("\n-----END ")
	lineSuffix  = []byte("-----")
)

const (
	Pkcs1 RsaWay = iota
	Pkcs8
)

type Keys struct {
	privateKey []byte
	publicKey  []byte
	way        RsaWay

	parsedPubKey *rsa.PublicKey
	parsedPriKey *rsa.PrivateKey
}

func NewInitKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *Keys {
	return &Keys{
		parsedPriKey: privateKey,
		parsedPubKey: publicKey,
	}
}

func NewKeys(privateKey []byte, publicKey []byte, way RsaWay) *Keys {
	return &Keys{
		privateKey: formatKey([]byte(`PRIVATE KEY`), privateKey),
		publicKey:  formatKey([]byte(`PUBLIC KEY`), publicKey),
		way:        way,
	}
}

func (k *Keys) GetWay() RsaWay {
	return k.way
}

func formatKey(typ, key []byte) []byte {
	buf := bytes.NewBuffer(startPrefix)
	buf.Write(typ)
	buf.Write(lineSuffix)
	buf.Write([]byte{'\n'})
	buf.Write(key)
	buf.Write(endPrefix)
	buf.Write(typ)
	buf.Write(lineSuffix)
	return buf.Bytes()
}

func (k *Keys) PrivateKey() (key *rsa.PrivateKey, err error) {
	if k.parsedPriKey == nil {
		p, _ := pem.Decode(k.privateKey)

		switch k.way {
		case Pkcs1:
			k.parsedPriKey, err = x509.ParsePKCS1PrivateKey(p.Bytes)
		case Pkcs8:
			var keyInf interface{}
			if keyInf, err = x509.ParsePKCS8PrivateKey(p.Bytes); err != nil {
				return
			}

			var ok bool
			if k.parsedPriKey, ok = keyInf.(*rsa.PrivateKey); !ok {
				err = fmt.Errorf("key type %v not supported pkcs8", p.Type)
			}
		default:
			err = fmt.Errorf("key type not supported")
		}
	}

	return k.parsedPriKey, err
}

func (k *Keys) PublicKey() (publicKey *rsa.PublicKey, err error) {
	if k.parsedPubKey == nil {
		p, _ := pem.Decode(k.publicKey)
		if p == nil {
			err = fmt.Errorf("public format failed: %s", k.publicKey)
			return
		}

		var pubAny any
		if pubAny, err = x509.ParsePKIXPublicKey(p.Bytes); err != nil {
			return
		}
		k.parsedPubKey = pubAny.(*rsa.PublicKey)
	}

	return k.parsedPubKey, err
}

type IRsa interface {
	Encrypt(content []byte) ([]byte, error)
	Decrypt(decrypted []byte) ([]byte, error)

	SafeEncrypt(content []byte) ([]byte, error)
	SafeDecrypt(decrypted []byte) ([]byte, error)

	MakeSign(hash crypto.Hash, content []byte) (string, error)
	CheckSign(hash crypto.Hash, content []byte, sign string) (err error)

	MakeSafeSign(hash crypto.Hash, content []byte) (string, error)
	CheckSafeSign(hash crypto.Hash, content []byte, sign string) (err error)

	LongContentEncrypt(data []byte) ([]byte, error)
	LongContentDecrypt(data []byte) ([]byte, error)

	LongContentEncryptBase64(data []byte) (string, error)
	LongContentDecryptBase64(decryptText string) ([]byte, error)

	LongContentEncryptSafeBase64(data []byte) (string, error)
	LongContentDecryptSafeBase64(decryptText string) ([]byte, error)
}

type ersa struct {
	key  *Keys
	hash crypto.Hash
}

func NewRsa(key *Keys) *ersa {
	return &ersa{key: key}
}

func (r *ersa) Encrypt(content []byte) ([]byte, error) {
	pub, err := r.key.PublicKey()
	if err != nil {
		return nil, err
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, content)
	if err != nil {
		return []byte{}, err
	}

	ret := make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
	base64.StdEncoding.Encode(ret, encrypted)
	return ret, nil
}

func (r *ersa) Decrypt(decrypted []byte) ([]byte, error) {
	priKey, err := r.key.PrivateKey()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, base64.StdEncoding.DecodedLen(len(decrypted)))
	n, err := base64.StdEncoding.Decode(buf, decrypted)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priKey, buf[:n])
}

func (r *ersa) SafeEncrypt(content []byte) ([]byte, error) {
	pub, err := r.key.PublicKey()
	if err != nil {
		return nil, err
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, content)
	if err != nil {
		return []byte{}, err
	}

	ret := make([]byte, base64.RawURLEncoding.EncodedLen(len(encrypted)))
	base64.RawURLEncoding.Encode(ret, encrypted)
	return ret, nil
}

func (r *ersa) SafeDecrypt(decrypted []byte) ([]byte, error) {
	priKey, err := r.key.PrivateKey()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(decrypted)))
	n, err := base64.RawURLEncoding.Decode(buf, decrypted)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priKey, buf[:n])
}

func (r *ersa) MakeSign(hash crypto.Hash, content []byte) (string, error) {
	priKey, err := r.key.PrivateKey()
	if err != nil {
		return "", err
	}

	hashed := r.algo(hash, content)
	b, err := rsa.SignPKCS1v15(rand.Reader, priKey, hash, hashed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), err
}

func (r *ersa) algo(hash crypto.Hash, content []byte) []byte {
	hs := hash.New()
	hs.Write(content)
	return hs.Sum(nil)
}

func (r *ersa) CheckSign(hash crypto.Hash, content []byte, sign string) (err error) {
	signature, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return
	}

	pubKey, err := r.key.PublicKey()
	if err != nil {
		return
	}

	hashed := r.algo(hash, content)
	return rsa.VerifyPKCS1v15(pubKey, hash, hashed, signature)
}

func (r *ersa) MakeSafeSign(hash crypto.Hash, content []byte) (string, error) {
	priKey, err := r.key.PrivateKey()
	if err != nil {
		return "", err
	}

	hashed := r.algo(hash, content)
	b, err := rsa.SignPKCS1v15(rand.Reader, priKey, hash, hashed)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), err
}

func (r *ersa) CheckSafeSign(hash crypto.Hash, content []byte, sign string) (err error) {
	signature, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		return
	}

	pubKey, err := r.key.PublicKey()
	if err != nil {
		return
	}

	hashed := r.algo(hash, content)
	return rsa.VerifyPKCS1v15(pubKey, hash, hashed, signature)
}

func (r *ersa) LongContentEncrypt(data []byte) ([]byte, error) {
	// pkcs1v15 明文消息不能超过密钥大小，并且默认会填充 11 字节，例: 密钥大小 256，明文最大长度为 256-11 = 245
	pubKey, err := r.key.PublicKey()
	if err != nil {
		return nil, err
	}
	step := pubKey.Size() - 11

	var encryptList []byte
	for i := 0; i < len(data); i += step {
		end := i + step
		if end > len(data) {
			end = len(data)
		}

		src := data[i:end] // 分段数据大小 0～244  245～489，  490~734
		//加密
		encryptPKCS1v15, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, src)
		if err != nil {
			return nil, err
		}
		encryptList = append(encryptList, encryptPKCS1v15...)
	}

	return encryptList, nil
}

func (r *ersa) LongContentDecrypt(data []byte) ([]byte, error) {
	prik, err := r.key.PrivateKey()
	if err != nil {
		return nil, err
	}

	step := prik.Size()
	var resultList []byte
	for i := 0; i < len(data); i += step {
		end := i + step
		if end > len(data) {
			end = len(data)
		}

		src := data[i:end] // 分段数据大小 0～244  245～489，  490~734

		//解密
		decryptPKCS1v15, err := rsa.DecryptPKCS1v15(rand.Reader, prik, src)

		if err != nil {
			return nil, err
		}
		resultList = append(resultList, decryptPKCS1v15...)
	}

	return resultList, nil
}

func (r *ersa) LongContentEncryptBase64(data []byte) (string, error) {
	encrypt, err := r.LongContentEncrypt(data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypt), nil
}

func (r *ersa) LongContentDecryptBase64(decryptText string) ([]byte, error) {
	decodeString, err := base64.StdEncoding.DecodeString(decryptText)
	if err != nil {
		return nil, err
	}

	return r.LongContentDecrypt(decodeString)
}

func (r *ersa) LongContentEncryptSafeBase64(data []byte) (string, error) {
	encrypt, err := r.LongContentEncrypt(data)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(encrypt), nil
}

func (r *ersa) LongContentDecryptSafeBase64(decryptText string) ([]byte, error) {
	decodeString, err := base64.RawURLEncoding.DecodeString(decryptText)
	if err != nil {
		return nil, err
	}

	return r.LongContentDecrypt(decodeString)
}
