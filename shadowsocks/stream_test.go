package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func TestStreamCipher(t *testing.T) {
	key, iv := make([]byte, 64), make([]byte, 64)
	for i := 0; i < 64; i++ {
		key[i] = 0x00
		iv[i] = 0x01
	}
	testStreamCipher(t, "aes-128-cfb", key, iv)
	testStreamCipher(t, "aes-192-cfb", key, iv)
	testStreamCipher(t, "aes-256-cfb", key, iv)
}

var streamPlaintextMap = map[string]string{
	"aes-128-cfb": "shadowsocks stream cipher test",
	"aes-192-cfb": "shadowsocks stream cipher test",
	"aes-256-cfb": "shadowsocks stream cipher test",
}

var streamCiphertextMap = map[string]string{
	"aes-128-cfb": "dde6be9f7d96b946fb8d215a5cc20c65c0828f94dcf9e4d31f3029f9373c",
	"aes-192-cfb": "3c96a82d50267547e875c8d256328e6e0f5838d9b395486c3e906b1a7286",
	"aes-256-cfb": "e4723de4148d44cef28c1f2b3acebbfd751f5247439e025f2691df6fb237",
}

func testStreamCipher(t *testing.T, method string, key []byte, iv []byte) {
	errMsg := method + ": "
	cipher, err := NewCipher(method, string(key))
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	var ok bool
	cipher, ok = cipher.(*streamCipher)
	if !ok {
		t.Fatal(errMsg + "cipher is not streamCipher")
	}
	err = cipher.(*streamCipher).InitEncrypt(iv[:cipher.IvSize()])
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	err = cipher.(*streamCipher).InitDecrypt(iv[:cipher.IvSize()])
	if err != nil {
		errMsg += err.Error()
		t.Fatal(errMsg)
	}
	plaintext := []byte(streamPlaintextMap[method])
	ciphertext, err := hex.DecodeString(streamCiphertextMap[method])
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
