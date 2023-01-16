package encrypt

import (
	"testing"
)

func TestEcb(t *testing.T) {
	ecb1 := NewAes(key, nil).ECB().NoPadding().Base64()
	testMethod(t, ecb1, true, []byte("4kVKIuzWQGPkESwisR2C5g=="))
}

func TestCbc(t *testing.T) {
	cbc1 := NewAes(key, iv).CBC().NoPadding().Base64()
	testMethod(t, cbc1, true, []byte("4kVKIuzWQGPkESwisR2C5g=="))
}

func TestCtr(t *testing.T) {
	ctr1 := NewAes(key, iv).CTR().NoPadding().Base64()
	testMethod(t, ctr1, true, []byte("F4V1Tnu/bALbRDUaJ1TwYQ=="))
}

// todo
func TestOfb(t *testing.T) {
	ofb1 := NewAes(key, iv).OFB().NoPadding().Base64()
	testMethod(t, ofb1, true, []byte("F48FvPw6GFRqqkTefznnZg=="))
}

func TestCfb(t *testing.T) {
	cfb1 := NewAes(key, iv).CFB().NoPadding().Base64()
	testMethod(t, cfb1, true, []byte("F/9KzJ+TMHaQCQZ2UY8SrQ=="))
}
