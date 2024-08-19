package encrypt

//
//func NewOfb(key, iv []byte) *OFB {
//	return &OFB{
//		Base: NewMethod(key),
//		iv:   iv,
//	}
//}
//
////  OFB TODO 这个有问题。 解析的不对。
//type OFB struct {
//	*Base
//	iv []byte
//}
//
//func (c *OFB) Encrypt(bytes []byte) []byte {
//	plainText := c.fill(bytes)
//	crypto := make([]byte, len(plainText))
//	stream := cipher.NewOFB(c.B.block, c.iv)
//	stream.XORKeyStream(crypto, plainText)
//
//	return c.encode(crypto)
//}
//
//func (c *OFB) Decrypt(bytes []byte) (dst []byte, err error) {
//	var src []byte
//	if src, err = c.decode(bytes); err != nil {
//		return
//	}
//
//	var text = make([]byte, len(src))
//	stream := cipher.NewOFB(c.B.block, c.iv)
//	stream.XORKeyStream(text, src)
//
//	return c.restore(text), nil
//}
