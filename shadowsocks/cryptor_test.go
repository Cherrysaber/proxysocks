package shadowsocks

import (
	"bytes"
	"io"
	"testing"
)

//var plaintextMap = map[string]string{
//	"aes-128-gcm": "shadowsocks aead cipher test",
//	"aes-192-gcm": "shadowsocks aead cipher test",
//	"aes-256-gcm": "shadowsocks aead cipher test",
//
//	"aes-128-cfb": "shadowsocks stream cipher test",
//	"aes-192-cfb": "shadowsocks stream cipher test",
//	"aes-256-cfb": "shadowsocks stream cipher test",
//}
//
//var ciphertextMap = map[string]string{
//	"aes-128-gcm": "aa67845082c56d611db9a3b9d3be21d28eb6ad63bb7d5b73e1edf881dada047311651eb11215ac4f94a4b26e9f01f80c42f91ccfbad24d0315c395f6d02f",
//	"aes-192-gcm": "a5bd84c46af593053d759df9319760be14bea0342a8d87d773a1f2e3499d6f9bdec82dfaa98cf267bace4593f0e13bac1acace763b623845ecc1adaed016",
//	"aes-256-gcm": "14100007eaa96eef311824297823f2f8ece8bc48212291d37a5e9a194a1fbd079f36fa5bbaeaf43fdd72e483004baf75f4b017aa165cd08b2c2d313e5281",
//
//	"aes-128-cfb": "dde6be9f7d96b946fb8d215a5cc20c65c0828f94dcf9e4d31f3029f9373c",
//	"aes-192-cfb": "3c96a82d50267547e875c8d256328e6e0f5838d9b395486c3e906b1a7286",
//	"aes-256-cfb": "e4723de4148d44cef28c1f2b3acebbfd751f5247439e025f2691df6fb237",
//}

type newCipher int

func (c newCipher) New([]byte) Cryptor {
	return c
}

func (newCipher) KeySize() int {
	return 0
}

func (c newCipher) DecFrom(r io.Reader, p []byte) (n int, err error) {
	n, err = r.Read(p)
	if err != nil {
		return
	}
	for i := range p {
		p[i]--
	}
	return
}

func (c newCipher) EncTo(w io.Writer, p []byte) (int, error) {
	for i := range p {
		p[i]++
	}
	return w.Write(p)
}

func (c newCipher) InitEncrypt(iv []byte) error {
	return nil
}

func (c newCipher) InitDecrypt(iv []byte) error {
	return nil
}

func (c newCipher) IvSize() int {
	return 0
}

func TestRegisterCipher(t *testing.T) {
	RegisterCipher("new", newCipher(0))
	key, iv := make([]byte, 64), make([]byte, 64)
	for i := 0; i < 64; i++ {
		key[i] = 0x00
		iv[i] = 0x01
	}
	nc, err := NewCipher("new", string(key))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte{0x00, 0x01, 0x02, 0x03}
	ciphertext := []byte{0x01, 0x02, 0x03, 0x04}
	buf := make([]byte, len(plaintext))
	rw := bytes.NewBuffer(ciphertext)

	_, err = nc.DecFrom(rw, buf)
	if err != nil {
		t.Fatal(err)
	}

	if string(buf) != string(plaintext) {
		t.Fatal("decrypt failed")
	}

	// test encrypt
	rw.Reset()
	_, err = nc.EncTo(rw, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(rw.Bytes()) != string(ciphertext) {
		t.Fatal("encrypt failed")
	}

}
