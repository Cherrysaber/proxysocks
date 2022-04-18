package socks5

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
)

func TestAuthNone(t *testing.T) {
	auth := NewAuthNone()
	if auth.Method() != AuthMethodNone {
		t.Error("auth method should be MethodNone 0x00")
	}
	if auth.Auth(nil) != nil {
		t.Error("auth should be ok")
	}
}

func TestNewAuthUserPassword(t *testing.T) {
	auth := NewAuthUserPassword("user", "password")
	if auth.Method() != AuthMethodUserPassword {
		t.Error("auth method should be ", AuthMethodUserPassword)
	}
	testAuthUserPasswordVerFail(t, auth)
	testAuthUserPasswordSuccess(t, auth)
	testAuthUserPasswordFail(t, auth)
	testAuthUserPasswordUnknownStatus(t, auth)
}

func testAuthUserPasswordVerFail(t *testing.T, auth AuthMethod) {
	rw := bytes.NewBuffer(nil)
	for i := 0; i < 256; i++ {
		if byte(i) == UserPasswordVer {
			continue
		}
		rw.Reset()
		rw.Write([]byte{byte(i), 0x00})
		err := auth.Auth(rw)
		targetErr := &s5Error{
			prefix: "AuthUserPassword",
			err:    errors.New("invalid version " + strconv.Itoa(i)),
		}
		if err.Error() != targetErr.Error() {
			t.Error("error should be ", targetErr, " but ", err)
		}
	}

}

func testAuthUserPasswordSuccess(t *testing.T, auth AuthMethod) {
	rw := bytes.NewBuffer([]byte{UserPasswordVer, UserPasswordSuccess})
	err := auth.Auth(rw)
	if err != nil {
		t.Error("auth should not be fail with ", err)
	}
}

func testAuthUserPasswordFail(t *testing.T, auth AuthMethod) {
	rw := bytes.NewBuffer([]byte{UserPasswordVer, UserPasswordFailure})
	err := auth.Auth(rw)
	targetErr := &s5Error{
		prefix: "AuthUserPassword",
		err:    errors.New("invalid user or password"),
	}
	if err.Error() != targetErr.Error() {
		t.Error("error should be ", targetErr, " but ", err)
	}
}

func testAuthUserPasswordUnknownStatus(t *testing.T, auth AuthMethod) {
	targetErr := &s5Error{
		prefix: "AuthUserPassword",
		err:    errors.New("unknown status code"),
	}
	rw := bytes.NewBuffer(nil)
	for i := 0; i < 256; i++ {
		if byte(i) == UserPasswordSuccess || byte(i) == UserPasswordFailure {
			continue
		}
		rw.Reset()
		rw.Write([]byte{UserPasswordVer, byte(i)})
		err := auth.Auth(rw)
		if targetErr.Error() != err.Error() {
			t.Error("error should be ", targetErr, " but ", err)
		}
	}
}

func TestAuthUserPasswordServer(t *testing.T) {
	m := map[string]string{"abc": "123456"}
	auth := NewAuthUserPasswordServer(m, true)
	testAuthUserPasswordServerVerFail(t, auth)
	testAuthUserPasswordServerSuccess(t, auth)
	testAuthUserPasswordServerFail1(t, auth)
	testAuthUserPasswordServerFail2(t, auth)
}

func testAuthUserPasswordServerVerFail(t *testing.T, auth AuthMethod) {
	rw := bytes.NewBuffer(nil)
	for i := 0; i < 256; i++ {
		if byte(i) == UserPasswordVer {
			continue
		}
		rw.Reset()
		rw.Write([]byte{byte(i), 0x00})
		err := auth.Auth(rw)
		targetErr := &s5Error{
			prefix: "AuthUserPasswordServer",
			err:    errors.New("invalid version " + strconv.Itoa(i)),
		}
		if err.Error() != targetErr.Error() {
			t.Error("error should be ", targetErr, " but ", err)
		}
	}
}

func testAuthUserPasswordServerSuccess(t *testing.T, auth AuthMethod) {
	user := append([]byte{byte(len("abc"))}, []byte("abc")...)
	password := append([]byte{byte(len("123456"))}, []byte("123456")...)
	buf := append([]byte{UserPasswordVer}, user...)
	buf = append(buf, password...)
	rw := bytes.NewBuffer(buf)
	err := auth.Auth(rw)
	if err != nil {
		t.Error("auth should not be fail with ", err)
	}
	buf = rw.Bytes()
	if buf[0] != UserPasswordVer {
		t.Errorf("auth version should be %d not %d ", UserPasswordVer, buf[0])
	}
	if buf[1] != UserPasswordSuccess {
		t.Errorf("auth status should be %d not %d ", UserPasswordSuccess, buf[1])
	}
}

// user not exist
func testAuthUserPasswordServerFail1(t *testing.T, auth AuthMethod) {
	user := append([]byte{byte(len("a"))}, []byte("a")...)
	password := append([]byte{byte(len("123456"))}, []byte("123456")...)
	buf := append([]byte{UserPasswordVer}, user...)
	buf = append(buf, password...)
	rw := bytes.NewBuffer(buf)
	err := auth.Auth(rw)
	targetErr := &s5Error{
		prefix: "AuthUserPasswordServer",
		err:    errors.New("invalid user or password"),
	}
	if err.Error() != targetErr.Error() {
		t.Error("error should be ", targetErr, " but ", err)
	}
}

// password not match
func testAuthUserPasswordServerFail2(t *testing.T, auth AuthMethod) {
	user := append([]byte{byte(len("abc"))}, []byte("abc")...)
	password := append([]byte{byte(len("223456"))}, []byte("223456")...)
	buf := append([]byte{UserPasswordVer}, user...)
	buf = append(buf, password...)
	rw := bytes.NewBuffer(buf)
	err := auth.Auth(rw)
	targetErr := &s5Error{
		prefix: "AuthUserPasswordServer",
		err:    errors.New("invalid user or password"),
	}
	if err.Error() != targetErr.Error() {
		t.Error("error should be ", targetErr, " but ", err)
	}
}
