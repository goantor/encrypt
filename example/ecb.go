package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

//var key, iv = []byte("HpMM0iJX6oA3SpgX"), []byte("qrRkjLZV2Hbgntoy")

func main() {
	var random = 1
	fmt.Println(random)
	b := make([]byte, 64/2)
	rand.Seed(time.Now().UnixNano())
	rand.Read(b)
	//fmt.Printf("%s\n", b)
	toString := hex.EncodeToString(b)
	fmt.Println(toString, len(toString))
	//encryptor := encript.NewECB(key).Aes().NoPadding().Base64()
	//crypto := encryptor.Encrypt([]byte("xxxx"))
	//fmt.Printf("%s\n", crypto)
}
