package trojan

import (
	"bytes"
	"testing"
)

func TestAuthFailure(t *testing.T) {
	a := AuthFailure("test")
	if a.Error() != "AuthFailure" {
		t.Error("AuthFailure != ", a.Error())
	}
	if string(a) != "test" {
		t.Error("test != ", string(a))
	}
}

func TestAuthPassword(t *testing.T) {
	rw := bytes.NewBuffer(nil)
	a := NewAuthPasswordSlice([]string{"test", "test2"}, true)
	if a.Method() != "password" {
		t.Error("password != ", a.Method())
	}
	rw.Reset()
	rw.Write(Hash("test"))
	if err := a.Auth(rw); err != nil {
		t.Error("AuthPassword does not match test")
	}
	rw.Reset()
	rw.Write(Hash("test3"))
	if err := a.Auth(rw); err == nil {
		t.Error("AuthPassword should not match test3")
	}
	m := map[string]int{
		"test":  1,
		"test2": 2,
	}
	a = NewAuthPasswordMap(m, true)
	rw.Reset()
	rw.Write(Hash("test"))
	if err := a.Auth(rw); err != nil {
		t.Error("AuthPassword does not match test")
	}
	rw.Reset()
	rw.Write(Hash("test3"))
	if err := a.Auth(rw); err == nil {
		t.Error("AuthPassword should not match test3")
	}
}
