// Copyright (c) 2022 Cherrysaber. All rights reserved.

package socks5

import (
	"net"
	"time"
)

// 和 net 库一致实现 Dial , Listen , DialUDP , ListenUDP 等

// Dial 使用给定的network、address连接到远程主机,
// hostPort为要代理的地址, auths为支持的认证方法, nil则使用AuthNone
func Dial(network, address, hostPort string, auths []AuthMethod) (net.Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	if auths == nil {
		auths = []AuthMethod{NewAuthNone()}
	}
	if err = clientHandshake(conn, hostPort, CmdConnect, auths); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialTimeout 使用给定的network、address连接到远程主机, 并设置超时时间,
// hostPort为要代理的地址, auths为支持的认证方法, nil则使用AuthNone
func DialTimeout(network, address, hostPort string, auths []AuthMethod, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}
	if auths == nil {
		auths = []AuthMethod{NewAuthNone()}
	}
	if err = ClientHandshakeTimeout(conn, hostPort, CmdConnect, auths, timeout); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// A Listener is a generic network listener for socks5 protocols.
// Multiple goroutines may invoke methods on a Listener simultaneously.
type Listener struct {
	net.Listener
	auths   []AuthMethod
	timeout time.Duration
}

// 默认握手成功回复Bytes
var defaultResponseBytes = []byte{Version, 0x00, 0x00, AddrTypeIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Accept 返回net.Conn, client请求的地址, 如果握手失败则返回对应的错误
func (l *Listener) Accept() (conn net.Conn, hostPort string, err error) {
	if conn, err = l.Listener.Accept(); err != nil {
		return
	}
	if hostPort, err = ServerHandshakeTimeout(conn, l.auths, l.timeout); err != nil {
		conn.Close()
		return
	}
	if _, err = conn.Write(defaultResponseBytes); err != nil {
		conn.Close()
		err = &s5Error{
			prefix: "Response",
			op:     "Flush to Writer",
			err:    err,
		}
		return
	}
	return
}

// Listen creates a Socks5 listener accepting connections on the given network address using net.Listen.
// A nil auths as equivalent to the AuthNone.
func Listen(network, address string, auths []AuthMethod) (*Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if auths == nil {
		auths = []AuthMethod{NewAuthNone()}
	}
	return &Listener{l, auths, 0}, nil
}

// ListenTimeout creates a Socks5 listener accepting connections on the given network address using net.Listen.
// A nil auths as equivalent to the AuthNone.
// i/o timeout will happen if client don't complete the handshake within the timeout.
func ListenTimeout(network, address string, auths []AuthMethod, timeout time.Duration) (*Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if auths == nil {
		auths = []AuthMethod{NewAuthNone()}
	}
	return &Listener{l, auths, timeout}, nil
}

// AcceptResponse 返回net.Conn, client请求的地址, 如果握手失败则返回对应的错误
// 使用用户构造的Response进行回复
func (l *Listener) AcceptResponse(responseCreate func(localAddress string, err error) *Response) (conn net.Conn, hostPort string, err error) {
	if conn, err = l.Listener.Accept(); err != nil {
		return
	}
	if hostPort, err = ServerHandshakeTimeout(conn, l.auths, l.timeout); err != nil {
		conn.Close()
		return
	}
	response := responseCreate(conn.LocalAddr().String(), err)
	if err = response.FlushTo(conn); err != nil {
		conn.Close()
		return
	}
	return
}
