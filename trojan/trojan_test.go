package trojan

import (
	"bytes"
	"testing"
)

func TestHandshake(t *testing.T) {
	hash := sha224("password")
	auth := NewAuthPasswordSlice([]string{string(hash)}, false)
	rw := bytes.NewBuffer(nil)
	err := clientHandshake(rw, "127.0.0.1:6666", "password")
	if err != nil {
		t.Fatal(err)
	}
	network, hostPort, err := serverHandshake(rw, auth)
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" {
		t.Fatal("network != tcp")
	}
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort, "!= 127.0.0.1:6666")
	}
}

func TestHandshakeError(t *testing.T) {
	hash := sha224("password")
	auth := NewAuthPasswordSlice([]string{string(hash)}, true)
	rw := bytes.NewBuffer(nil)
	err := clientHandshake(rw, "127.0.0.1:6666", "password2")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = serverHandshake(rw, auth)
	if err.Error() != AuthFailure("1").Error() {
		t.Fatal(err)
	}
	hash = sha224("password2")
	if string(err.(AuthFailure)) != string(hash) {
		t.Fatal("AuthFailure(err) != sha224(\"password2\")")
	}
}
