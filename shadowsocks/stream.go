package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"strconv"
)

type streamInfo struct {
	keyLen    int
	ivLen     int
	newCipher func(key, iv []byte, op int) (cipher.Stream, error)
}

func (si *streamInfo) KeySize() int {
	return si.keyLen
}

func (si *streamInfo) New(key []byte) Cryptor {
	return &streamCipher{
		enc:  nil,
		dec:  nil,
		key:  key,
		info: si,
	}
}

var streamMethod = map[string]*streamInfo{
	"aes-128-cfb": {16, 16, newCFBStream},
	"aes-192-cfb": {24, 16, newCFBStream},
	"aes-256-cfb": {32, 16, newCFBStream},
}

func init() {
	for method, si := range streamMethod {
		RegisterCipher(method, si)
	}
}

type streamCipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *streamInfo
}

func (s *streamCipher) DecFrom(r io.Reader, p []byte) (int, error) {
	if s.dec != nil {
		return s.decFrom(r, p)
	}
	// init Cipher
	iv := make([]byte, s.info.ivLen)
	if _, err := io.ReadFull(r, iv); err != nil {
		return 0, &ssError{
			prefix: "streamCipher",
			op:     "Read iv Bytes",
			err:    err,
		}
	}
	if err := s.InitDecrypt(iv); err != nil {
		return 0, &ssError{
			prefix: "streamCipher",
			op:     "Init Decrypt",
			err:    err,
		}
	}
	return s.decFrom(r, p)
}

func (s *streamCipher) decFrom(r io.Reader, dst []byte) (n int, err error) {
	src := make([]byte, len(dst))
	if n, err = r.Read(src); err != nil {
		err = &ssError{
			prefix: "streamCipher",
			op:     "Read src Bytes",
			err:    err,
		}
		return
	}
	s.dec.XORKeyStream(dst, src[:n])
	return n, nil
}

func (s *streamCipher) EncTo(w io.Writer, p []byte) (int, error) {
	if s.enc != nil {
		return s.encTo(w, p)
	}
	// init Cipher
	iv := make([]byte, s.info.ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return 0, &ssError{
			prefix: "streamCipher",
			op:     "Read iv Bytes",
			err:    err,
		}
	}
	if err := s.InitEncrypt(iv); err != nil {
		return 0, &ssError{
			prefix: "streamCipher",
			op:     "Init Encrypt",
			err:    err,
		}
	}
	// write iv
	if _, err := w.Write(iv); err != nil {
		return 0, &ssError{
			prefix: "streamCipher",
			op:     "Write iv Bytes",
			err:    err,
		}
	}
	return s.encTo(w, p)
}

func (s *streamCipher) encTo(w io.Writer, src []byte) (n int, err error) {
	dst := make([]byte, len(src))
	s.enc.XORKeyStream(dst, src)
	if n, err = w.Write(dst); err != nil {
		err = &ssError{
			prefix: "streamCipher",
			op:     "Write dst Bytes",
			err:    err,
		}
		return
	}
	return n, nil
}

func (s *streamCipher) InitEncrypt(iv []byte) (err error) {
	if len(iv) != s.info.ivLen {
		return errors.New("invalid iv size " + strconv.Itoa(len(iv)))
	}
	s.enc, err = s.info.newCipher(s.key, iv, Encrypt)
	return err
}

func (s *streamCipher) InitDecrypt(iv []byte) (err error) {
	if len(iv) != s.info.ivLen {
		return errors.New("invalid iv size " + strconv.Itoa(len(iv)))
	}
	s.dec, err = s.info.newCipher(s.key, iv, Decrypt)
	return err
}

func (s *streamCipher) KeySize() int {
	return s.info.keyLen
}

func (s *streamCipher) IvSize() int {
	return s.info.ivLen
}

func newCFBStream(key, iv []byte, op int) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if op == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}
