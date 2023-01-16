package encrypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBase64Wrap(t *testing.T) {
	wrap := &Base64Wrap{}
	original := []byte("1234567890abcdefghijklmnopqrstuvw")

	wrapped := wrap.Encode(original)
	t.Logf("got wrapped bytes: %s\n", wrapped)

	decoded, err := wrap.Decode(wrapped)
	assert.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestHexWrapper(t *testing.T) {
	wrap := &HexWrap{}
	original := []byte("1234567890abcdefghijklmnopqrstuvw")

	wrapped := wrap.Encode(original)
	t.Logf("got wrapped bytes: %s\n", wrapped)

	decoded, err := wrap.Decode(wrapped)
	assert.NoError(t, err)

	assert.Equal(t, original, decoded)
}
