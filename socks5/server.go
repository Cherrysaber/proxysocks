// Copyright (c) 2022 Cherrysaber. All rights reserved.

package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

// ServerHandshake server执行socks5握手, 握手成功返回client请求的hostPort
// ServerHandshake无论握手成功与否, 都不会发送Response数据, 需要用户自动构造Response回复
func ServerHandshake(conn net.Conn, auths []AuthMethod) (hostPort string, err error) {
	return serverHandshake(conn, auths)
}

// ServerHandshakeTimeout server设置超时时间执行socks5握手, 握手成功返回client请求的hostPort
// ServerHandshakeTimeout无论握手成功与否, 都不会发送Response数据, 需要用户自动构造Response回复
func ServerHandshakeTimeout(conn net.Conn, auths []AuthMethod, timeout time.Duration) (hostPort string, err error) {
	if timeout > 0 {
		// set timeout
		if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			err = &s5Error{
				prefix: "serverHandshake",
				op:     "SetDeadline",
				err:    err,
			}
			return
		}

		// reset timeout
		defer func() {
			if e := conn.SetDeadline(time.Time{}); e != nil {
				panic(e)
			}
		}()
	}

	return serverHandshake(conn, auths)
}

// 握手开始
// server receive hello request
// server select auth method
// server send hello response
// server using auth method to do auth
// server receive request
// parse request to get hostPort
// 握手结束
func serverHandshake(rw io.ReadWriter, auths []AuthMethod) (hostPort string, err error) {
	// server receive hello request
	helloRequest := HelloRequest{}
	if err = helloRequest.ParseFrom(rw); err != nil {
		return
	}
	helloResponse := HelloResponse{Version, AuthMethodNoAcceptableMethods}
	// server select auth method
	var auth AuthMethod
	for i := range auths {
		if bytes.Index(helloRequest.Methods, []byte{auths[i].Method()}) != -1 {
			helloResponse.Method = auths[i].Method()
			auth = auths[i]
			break
		}
	}
	// server send hello response
	if err = helloResponse.FlushTo(rw); err != nil {
		return
	}
	if auth == nil {
		err = &s5Error{
			prefix: "serverHandshake",
			err:    errors.New("no acceptable auth method"),
		}
		return
	}

	// Auth
	if err = auth.Auth(rw); err != nil {
		return
	}

	// server receive request
	request := Request{}
	if err = request.ParseFrom(rw); err != nil {
		return
	}

	// parse request to get hostPort
	return ParseHostPort(request.AddrType, request.DstAddr, request.DstPort)
}
