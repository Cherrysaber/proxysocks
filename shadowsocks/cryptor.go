// Copyright (c) 2022 Cherrysaber. All rights reserved.

package shadowsocks

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
)

const (
	Decrypt = 0
	Encrypt = 1
)

var keyMap = map[string][]byte{}

func EvpBytesToKey(password string, keyLen int) []byte {
	keyStr := fmt.Sprintf("%s-%d", password, keyLen)
	if key, ok := keyMap[keyStr]; ok {
		return key
	}

	h := md5.New()
	ms := make([]byte, 0)
	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	for data := []byte(password); len(ms) < keyLen; {
		h.Write(data)
		m := h.Sum(nil)
		h.Reset()
		data = append(m, []byte(password)...)
		ms = append(ms, m...)
	}

	key := ms[:keyLen]
	keyMap[keyStr] = key
	return key
}

type cipherInfo interface {
	New([]byte) Cryptor
	KeySize() int
}

var cipherMethod = map[string]cipherInfo{}

func RegisterCipher(name string, c cipherInfo) {
	cipherMethod[name] = c
}

type Cryptor interface {
	DecFrom(r io.Reader, p []byte) (int, error)
	EncTo(w io.Writer, p []byte) (int, error)
	KeySize() int
	IvSize() int
}

func NewCipher(method, password string) (Cryptor, error) {
	ci, ok := cipherMethod[method]
	if !ok {
		err := errors.New("Unsupported method: " + method)
		return nil, err
	}
	key := EvpBytesToKey(password, ci.KeySize())
	c := ci.New(key)
	return c, nil
}
