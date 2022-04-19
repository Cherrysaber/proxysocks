package trojan

import "testing"

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
	a := NewAuthPasswordSlice([]string{"test", "test2"}, false)
	if a.Method() != "password" {
		t.Error("password != ", a.Method())
	}
	if !a.Auth("test") {
		t.Error("AuthPassword does not match test")
	}
	if a.Auth("test3") {
		t.Error("AuthPassword should not match test3")
	}
	m := map[string]int{
		"test":  1,
		"test2": 2,
	}
	a = NewAuthPasswordMap(m, false)
	if !a.Auth("test") {
		t.Error("AuthPassword does not match test")
	}
	if a.Auth("test3") {
		t.Error("AuthPassword should not match test3")
	}
}
