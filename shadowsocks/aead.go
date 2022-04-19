package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/hkdf"
)

const (
	// payloadSizeMask is the maximum size of payload in bytes.
	payloadSizeMask = 0x3FFF    // 16*1024 - 1
	bufSize         = 17 * 1024 // >= 2+aead.Overhead()+payloadSizeMask+aead.Overhead()
)

type aeadInfo struct {
	keyLen    int
	ivLen     int
	newCipher func([]byte) (cipher.AEAD, error)
}

func (ai *aeadInfo) KeySize() int {
	return ai.keyLen
}

func (ai *aeadInfo) New(key []byte) Cryptor {
	return &aeadCipher{
		enc:  nil,
		dec:  nil,
		key:  key,
		info: ai,
	}
}

var aeadMethod = map[string]*aeadInfo{
	"aes-128-gcm": {16, 16, aesGCM},
	"aes-192-gcm": {24, 24, aesGCM},
	"aes-256-gcm": {32, 32, aesGCM},
}

func init() {
	for method, ai := range aeadMethod {
		RegisterCipher(method, ai)
	}
}

type aeadCipher struct {
	enc      cipher.AEAD
	encNonce [32]byte
	dec      cipher.AEAD
	decNonce [32]byte
	key      []byte
	info     *aeadInfo

	buf  [bufSize]byte
	r, w int
}

func (a *aeadCipher) InitDecrypt(iv []byte) (err error) {
	if len(iv) != a.info.ivLen {
		return errors.New("invalid iv size " + strconv.Itoa(len(iv)))
	}
	sKey := make([]byte, a.info.keyLen)
	hkdfSHA1(a.key, iv, []byte("ss-subkey"), sKey)
	a.dec, err = a.info.newCipher(sKey)
	return err
}

func (a *aeadCipher) DecFrom(r io.Reader, p []byte) (int, error) {
	if a.r == a.w {
		if len(p) > bufSize {
			return a.decFrom(r, p)
		}
		a.r = 0
		var err error
		a.w, err = a.decFrom(r, a.buf[:])
		if err != nil {
			return a.w, err
		}
	}
	n := copy(p, a.buf[a.r:a.w])
	a.r += n
	return n, nil
}

func (a *aeadCipher) decFrom(r io.Reader, p []byte) (int, error) {
	if a.dec != nil {
		return a.decryptFrom(r, p)
	}
	// init Cipher
	iv := make([]byte, a.info.ivLen)
	if _, err := io.ReadFull(r, iv); err != nil {
		return 0, &ssError{
			prefix: "aeadCipher",
			op:     "Read iv",
			err:    err,
		}
	}
	if err := a.InitDecrypt(iv); err != nil {
		return 0, &ssError{
			prefix: "aeadCipher",
			op:     "Init Decrypt",
			err:    err,
		}
	}
	return a.decryptFrom(r, p)
}

func (a *aeadCipher) decryptFrom(r io.Reader, p []byte) (n int, err error) {
	nonce := a.decNonce[:a.dec.NonceSize()]
	tagLen := a.dec.Overhead()

	// decrypt payload size
	n, err = io.ReadFull(r, p[:2+tagLen])
	if err != nil {
		err = &ssError{
			prefix: "aeadCipher",
			op:     "Read Payload Size",
			err:    err,
		}
		return
	}
	if _, err = a.dec.Open(p[:0], nonce, p[:n], nil); err != nil {
		err = &ssError{
			prefix: "aeadCipher",
			op:     "Decrypt Payload Size",
			err:    err,
		}
		return
	}

	increment(nonce)

	// decrypt payload
	size := (int(p[0])<<8 + int(p[1])) & payloadSizeMask
	if size+tagLen > len(p) {
		err = &ssError{
			prefix: "aeadCipher",
			err:    io.ErrShortBuffer,
		}
		return
	}
	n, err = io.ReadFull(r, p[:size+tagLen])
	if err != nil {
		err = &ssError{
			prefix: "aeadCipher",
			op:     "Read Payload",
			err:    err,
		}
		return
	}

	if _, err = a.dec.Open(p[:0], nonce, p[:n], nil); err != nil {
		err = &ssError{
			prefix: "aeadCipher",
			op:     "Decrypt Payload",
			err:    err,
		}
	}

	increment(nonce)

	return size, err
}

func (a *aeadCipher) EncTo(w io.Writer, p []byte) (int, error) {
	if a.enc != nil {
		return a.encTo(w, p)
	}
	// init Cipher
	iv := make([]byte, a.info.ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return 0, &ssError{
			prefix: "aeadCipher",
			op:     "Read iv",
			err:    err,
		}
	}
	if err := a.InitEncrypt(iv); err != nil {
		return 0, &ssError{
			prefix: "aeadCipher",
			op:     "Init Encrypt",
			err:    err,
		}
	}
	// write iv
	if _, err := w.Write(iv); err != nil {
		return 0, &ssError{
			prefix: "aeadCipher",
			op:     "Write iv",
			err:    err,
		}
	}
	return a.encTo(w, p)
}

func (a *aeadCipher) encTo(w io.Writer, p []byte) (n int, err error) {
	nonce := a.encNonce[:a.enc.NonceSize()]
	tagLen := a.enc.Overhead()
	off := 2 + tagLen
	var buf [bufSize]byte
	n = 0
	for nr := payloadSizeMask; n < len(p); n += nr { // write piecemeal in max payload size chunks
		if tail := len(p) - n; tail < payloadSizeMask {
			nr = tail
		}
		buf[0], buf[1] = byte(nr>>8), byte(nr) // big-endian payload size
		a.enc.Seal(buf[:0], nonce, buf[:2], nil)
		increment(nonce)
		a.enc.Seal(buf[:off], nonce, p[n:n+nr], nil)
		increment(nonce)
		if _, err = w.Write(buf[:off+nr+tagLen]); err != nil {
			err = &ssError{
				prefix: "aeadCipher",
				op:     "Write Encrypt Bytes",
				err:    err,
			}
			return
		}
	}
	return
}

func (a *aeadCipher) InitEncrypt(iv []byte) (err error) {
	if len(iv) != a.info.ivLen {
		return errors.New("invalid iv size " + strconv.Itoa(len(iv)))
	}
	sKey := make([]byte, a.info.keyLen)
	hkdfSHA1(a.key, iv, []byte("ss-subkey"), sKey)
	a.enc, err = a.info.newCipher(sKey)
	return err
}

func (a *aeadCipher) KeySize() int {
	return a.info.keyLen
}

func (a *aeadCipher) IvSize() int {
	return a.info.ivLen
}

func hkdfSHA1(secret, salt, info, key []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(err) // should never happen
	}
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
