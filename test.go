package encrypt

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

var (
	key, iv = []byte("HpMM0iJX6oA3SpgX"), []byte("qrRkjLZV2Hbgntoy")
)

func generate() []byte {
	var zm = make([]byte, 0)
	for i := 32; i < 127; i++ {
		zm = append(zm, byte(i))
	}

	rand.Seed(time.Now().UnixNano())
	randLength := rand.Intn(999)
	b := make([]byte, 0)
	for ; randLength >= 0; randLength-- {
		i := rand.Intn(93)
		b = append(b, zm[i])
	}

	fmt.Printf("generate: %s\n", string(b))
	return b
}

func testMethod(t *testing.T, encryptor IEncrypt, useXXXX bool, result []byte) {
	var text = make([]byte, 0)
	if useXXXX {
		text = []byte("xq1_ddq")
	} else {
		text = generate()
	}

	encrypted := encryptor.Encrypt(text)
	t.Logf("encrypted: %s\n", encrypted)
	if useXXXX {
		t.Logf("encrypted Equal <%s>: %v\n", result, bytes.Equal(encrypted, result))
		if !bytes.Equal(encrypted, result) {
			t.Error("result failed to be equal")
		}
	}

	t2, err := encryptor.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, text, t2)
}
