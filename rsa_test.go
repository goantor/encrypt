package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestLongContent(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()

	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	pubK, err := x509.ParsePKIXPublicKey(pkixpub)
	if err != nil {
		t.Fatal(err)
	}

	keys := NewInitKeys(priv, pubK.(*rsa.PublicKey))
	encrypt := NewRsa(keys)

	rawStr := `gDhERYLAQNbwTqE6LABrGdovjXFkCO7+U0xbzVfIgY9+cgmfeKGOmie05WD8gVah/QG5Ys9FpIIpah3t9KNvcrKqhEIkAAs1UQ6foIvY5SAX8BJsSqwFp/B8a2Fbl35u1ASj0XGGcqJSQTZ9JP/DDT4KfcNsJ1UQrg7X7g7swCT3vxL7xmU1l2o+mpbYIjAn9bEbfZp8t8rKFNyJn9UoqpQLMYvazkXUDOfTMBSdg65s38qgrqavc4X0G8QkhDNfAsPmsPnPIp1zsSvVUelHVBCMX9ORcXkBdolSwdIo2arbBVSbnLw92V4tajJ6oE7WSOUfIFvp38k9dqcIxRWpqlGzCMc7ymn7+FeRMM2E6Wc2FwCp3+NVHqqprhh4KtjKrG+0Z2ZsPAqqcFezL87tcijNfVfGPXP+V7L8atJXyIrWxr0jj20Kja9xDuPTkV48U41Kp3rnx91MyplaU/24HNOoM9Zlse84rR5Ok93Hd4AZpFFkyLP+BFCQRsaPOQeY71IXDgbbporiUXGICJpSzOFU0zeIPLj61tTcvjZpekQLIewg8iEFGbhccwJ7mIZnm3amS8r6/ZV4IyEdFEGWXFXqAvqua2Sbn9CqxLbGF670lDrFhisBTLbU0GLrNcUuq634pISBtphCs8geHorbjr2SeTIlRGnKdhxeF7uTsAI="}`
	ed, err := encrypt.LongContentEncrypt([]byte(rawStr))
	if err != nil {
		t.Fatal(err)
	}
	hexEnc := hex.EncodeToString(ed)
	t.Log(hexEnc)

	de, err := encrypt.LongContentDecrypt(ed)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(de))

	base64, err := encrypt.LongContentEncryptBase64([]byte(rawStr))
	if err != nil {
		return
	}

	decryptBase64, err := encrypt.LongContentDecryptBase64(base64)
	if err != nil {
		return
	}

	t.Log(string(decryptBase64))
}
