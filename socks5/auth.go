// Copyright (c) 2022 Cherrysaber. All rights reserved.

package socks5

import (
	"errors"
	"io"
	"strconv"
)

// 实现了 SOCKS5 认证方式的接口
// 实现了 AuthNone 和 AuthUserPassword
// todo AuthGssapi

// AuthMethod socks5 认证方式接口
type AuthMethod interface {
	// Method return method byte
	Method() byte
	// Auth 认证具体实现
	// 如果 error 为 nil, 表示认证成功
	Auth(rw io.ReadWriter) error
}

// AuthNone 无需认证
type AuthNone int

func (a *AuthNone) Method() byte {
	return AuthMethodNone
}

func (a *AuthNone) Auth(io.ReadWriter) error {
	return nil
}

const (
	UserPasswordVer     = 0x01
	UserPasswordSuccess = 0x00
	UserPasswordFailure = 0x01
)

// AuthUserPassword 客户端用户名和密码认证
type AuthUserPassword struct {
	User     string
	Password string
}

func (a *AuthUserPassword) Method() byte {
	return AuthMethodUserPassword
}

func (a *AuthUserPassword) Auth(rw io.ReadWriter) error {
	// make auth bytes
	//
	//	+-----+------+--------+------+----------+
	//	| Ver | ULen |  User  | PLen | Password |
	//	+-----+------+--------+------+----------+
	//	|  1  |  1   |Variable|   1  | Variable |
	//	+-----+------+--------+------+----------+
	//
	buf := make([]byte, 2, 3+len(a.User)+len(a.Password))
	buf[0], buf[1] = UserPasswordVer, byte(len(a.User))
	buf = append(buf, []byte(a.User)...)
	buf = append(buf, byte(len(a.Password)))
	buf = append(buf, []byte(a.Password)...)

	if _, err := rw.Write(buf); err != nil {
		return &s5Error{
			prefix: "AuthUserPassword",
			err:    err,
		}
	}

	// +-----+--------+
	// | Ver | Status |
	// +-----+--------+
	// |  1  |   1    |
	// +-----+--------+
	buf = make([]byte, 2)
	if _, err := io.ReadFull(rw, buf); err != nil {
		return &s5Error{
			prefix: "AuthUserPassword",
			err:    err,
		}
	}

	if buf[0] != UserPasswordVer {
		return &s5Error{
			prefix: "AuthUserPassword",
			err:    errors.New("invalid version " + strconv.Itoa(int(buf[0]))),
		}
	}

	if buf[1] == UserPasswordSuccess {
		return nil
	}

	if buf[1] == UserPasswordFailure {
		return &s5Error{
			prefix: "AuthUserPassword",
			err:    errors.New("invalid user or password"),
		}
	}

	return &s5Error{
		prefix: "AuthUserPassword",
		err:    errors.New("unknown status code"),
	}
}

// AuthUserPasswordServer 服务端用户名和密码认证
type AuthUserPasswordServer struct {
	// map[user]password
	Map map[string]string
	// 认证失败,是否回复客户端
	Reply bool
}

func (a *AuthUserPasswordServer) Method() byte {
	return AuthMethodUserPassword
}

func (a *AuthUserPasswordServer) Auth(rw io.ReadWriter) error {
	// read auth bytes
	//
	//	+-----+------+--------+------+----------+
	//	| Ver | ULen |  User  | PLen | Password |
	//	+-----+------+--------+------+----------+
	//	|  1  |  1   |Variable|   1  | Variable |
	//	+-----+------+--------+------+----------+
	//
	buf := make([]byte, 1)
	if _, err := rw.Read(buf); err != nil {
		return &s5Error{
			prefix: "AuthUserPasswordServer",
			op:     "Read Version",
			err:    err,
		}
	}

	if buf[0] != UserPasswordVer {
		return &s5Error{
			prefix: "AuthUserPasswordServer",
			err:    errors.New("invalid version " + strconv.Itoa(int(buf[0]))),
		}
	}

	// read user length
	if _, err := rw.Read(buf); err != nil {
		return &s5Error{
			prefix: "AuthUserPasswordServer",
			op:     "Read User Length",
			err:    err,
		}
	}

	// read user bytes
	user := make([]byte, buf[0])
	if _, err := io.ReadFull(rw, user); err != nil {
		return &s5Error{
			prefix: "AuthUserPasswordServer",
			op:     "Read User Bytes",
			err:    err,
		}
	}

	// read password length
	if _, err := rw.Read(buf); err != nil {
		return &s5Error{
			prefix: "AuthUserPasswordServer",
			op:     "Read Password Length",
			err:    err,
		}
	}

	// read password bytes
	password := make([]byte, buf[0])
	if _, err := io.ReadFull(rw, password); err != nil {
		return &s5Error{
			prefix: "AuthUserPasswordServer",
			op:     "Read Password Bytes",
			err:    err,
		}
	}

	// match user and password
	// 认证成功或者失败, 发送 reply bytes 后不处理错误,
	// 如果 write 有错误 在上层继续调用时处理
	if pass, ok := a.Map[string(user)]; ok && pass == string(password) {
		// reply 不处理错误
		rw.Write([]byte{UserPasswordVer, UserPasswordSuccess})
		return nil
	}

	if a.Reply {
		rw.Write([]byte{UserPasswordVer, UserPasswordFailure})
	}

	return &s5Error{
		prefix: "AuthUserPasswordServer",
		err:    errors.New("invalid user or password"),
	}
}

var authNone = AuthNone(0)

// NewAuthNone return AuthNone
func NewAuthNone() *AuthNone {
	return &authNone
}

// NewAuthUserPassword create AuthUserPassword by user and password
func NewAuthUserPassword(user, password string) *AuthUserPassword {
	return &AuthUserPassword{
		User:     user,
		Password: password,
	}
}

// NewAuthUserPasswordServer create AuthUserPasswordServer by map[user]password
func NewAuthUserPasswordServer(m map[string]string, reply bool) *AuthUserPasswordServer {
	return &AuthUserPasswordServer{
		Map:   m,
		Reply: reply,
	}
}
