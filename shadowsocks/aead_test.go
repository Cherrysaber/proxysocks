package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

var aeadPlaintextMap = map[string]string{
	"aes-128-gcm": "shadowsocks aead cipher test",
	"aes-192-gcm": "shadowsocks aead cipher test",
	"aes-256-gcm": "shadowsocks aead cipher test",
}

var aeadCiphertextMap = map[string]string{
	"aes-128-gcm": "aa67845082c56d611db9a3b9d3be21d28eb6ad63bb7d5b73e1edf881dada047311651eb11215ac4f94a4b26e9f01f80c42f91ccfbad24d0315c395f6d02f",
	"aes-192-gcm": "a5bd84c46af593053d759df9319760be14bea0342a8d87d773a1f2e3499d6f9bdec82dfaa98cf267bace4593f0e13bac1acace763b623845ecc1adaed016",
	"aes-256-gcm": "14100007eaa96eef311824297823f2f8ece8bc48212291d37a5e9a194a1fbd079f36fa5bbaeaf43fdd72e483004baf75f4b017aa165cd08b2c2d313e5281",
}

func TestAeadCipher(t *testing.T) {
	key, iv := make([]byte, 64), make([]byte, 64)
	for i := 0; i < 64; i++ {
		key[i] = 0x00
		iv[i] = 0x01
	}
	testAeadCipher(t, "aes-128-gcm", key, iv)
	testAeadCipher(t, "aes-192-gcm", key, iv)
	testAeadCipher(t, "aes-256-gcm", key, iv)
}

func testAeadCipher(t *testing.T, method string, key []byte, iv []byte) {
	errMsg := method + ": "
	cipher, err := NewCipher(method, string(key))
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	var ok bool
	cipher, ok = cipher.(*aeadCipher)
	if !ok {
		t.Fatal(errMsg + "cipher is not aeadCipher")
	}
	err = cipher.(*aeadCipher).InitEncrypt(iv[:cipher.IvSize()])
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	err = cipher.(*aeadCipher).InitDecrypt(iv[:cipher.IvSize()])
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	plaintext := []byte(aeadPlaintextMap[method])
	ciphertext, err := hex.DecodeString(aeadCiphertextMap[method])
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	rw := bytes.NewBuffer(ciphertext)
	buf := make([]byte, len(plaintext))

	// test decrypt
	n, err := cipher.DecFrom(rw, buf)
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	if string(buf[:n]) != string(plaintext) {
		errMsg += "decrypt failed"
		t.Fatal(errMsg)
	}

	// test encrypt
	rw.Reset()
	_, err = cipher.EncTo(rw, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(rw.Bytes()) != string(ciphertext) {
		errMsg += "encrypt failed"
		t.Fatal(errMsg)
	}

	// test random plaintext
	plaintext = make([]byte, 1024)
	if _, err = io.ReadFull(rand.Reader, plaintext); err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	rw.Reset()
	cipher, err = NewCipher(method, string(key))
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	_, err = cipher.EncTo(rw, plaintext)
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	ciphertext = rw.Bytes()

	rw.Reset()
	rw.Write(ciphertext)
	buf = make([]byte, len(plaintext))
	_, err = cipher.DecFrom(rw, buf)
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	if string(buf) != string(plaintext) {
		errMsg += "DecFrom and EncTo failed"
		t.Fatal(errMsg)
	}

}
