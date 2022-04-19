package trojan

import (
	"crypto/sha256"
	"fmt"
)

var crlf = "\r\n"

var hashMap = map[string][]byte{}

func sha224(password string) []byte {
	if hash, ok := hashMap[password]; ok {
		return hash
	}
	h224 := sha256.New224()
	h224.Write([]byte(password))
	hash := fmt.Sprintf("%x", h224.Sum(nil))
	hashMap[password] = []byte(hash)
	return []byte(hash)
}

func Hash(password string) []byte {
	return sha224(password)
}

type tjError struct {
	prefix string
	op     string
	err    error
}

func (e *tjError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := e.prefix
	if e.op != "" {
		s += " " + e.op
	}
	if e.err != nil {
		s += ": " + e.err.Error()
	}
	return s
}

func (e *tjError) Unwrap() error {
	return e.err
}
