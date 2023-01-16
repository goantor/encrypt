package encrypt

import (
	"testing"
)

func init() {
	//key = key[:8]
	//iv = iv[:8]
}

func TestDesEcb(t *testing.T) {
	ecb1 := NewDes(key, nil).ECB().NoPadding().Base64()
	testMethod(t, ecb1, true, []byte("e6RX5zK9A6E="))
}

func TestDesCbc(t *testing.T) {
	cbc1 := NewDes(key, iv).CBC().NoPadding().Base64()
	testMethod(t, cbc1, true, []byte("MbfnVmf7v8w="))
}

func TestDesCtr(t *testing.T) {
	ctr1 := NewDes(key, iv).CTR().NoPadding().Base64()
	testMethod(t, ctr1, true, []byte("+Ehw9VOg8bA="))
}

// todo 区块链
func TestDesOfb(t *testing.T) {
	ofb1 := NewDes(key, iv).OFB().NoPadding().Base64()
	testMethod(t, ofb1, true, []byte("+Cwll2hgK8I="))
}

func TestDesCfb(t *testing.T) {
	cfb1 := NewDes(key, iv).CFB().NoPadding().Base64()
	testMethod(t, cfb1, true, []byte("F/9KzJ+TMHaQCQZ2UY8SrQ=="))
}
