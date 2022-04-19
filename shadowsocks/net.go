package shadowsocks

import (
	"net"
	"time"
)

type Conn struct {
	net.Conn
	cryptor Cryptor
}

func (c *Conn) Read(p []byte) (int, error) {
	return c.cryptor.DecFrom(c.Conn, p)
}

func (c *Conn) Write(p []byte) (int, error) {
	return c.cryptor.EncTo(c.Conn, p)
}

func Dial(network, address, hostPort, method, password string) (*Conn, error) {
	cryptor, err := NewCipher(method, password)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	ss := &Conn{Conn: conn, cryptor: cryptor}
	if err = clientHandshake(ss, hostPort); err != nil {
		ss.Close()
		return nil, err
	}
	return ss, nil
}

func DialTimeout(network, address, hostPort, method, password string, timeout time.Duration) (*Conn, error) {
	cryptor, err := NewCipher(method, password)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}
	ss := &Conn{Conn: conn, cryptor: cryptor}
	if err = ClientHandshakeTimeout(ss, hostPort, timeout); err != nil {
		ss.Close()
		return nil, err
	}
	return ss, nil
}

type Listener struct {
	net.Listener
	method, password string
	timeout          time.Duration
}

func (l *Listener) Accept() (conn net.Conn, hostPort string, err error) {
	conn, err = l.Listener.Accept()
	if err != nil {
		return
	}
	var cryptor Cryptor
	cryptor, err = NewCipher(l.method, l.password)
	if err != nil {
		conn.Close()
		return
	}
	conn = &Conn{Conn: conn, cryptor: cryptor}
	if hostPort, err = ServerHandshakeTimeout(conn, l.timeout); err != nil {
		conn.Close()
	}
	return
}

func Listen(network, address, method, password string) (*Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &Listener{l, method, password, 0}, nil
}

func ListenTimeout(network, address, method, password string, timeout time.Duration) (*Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &Listener{l, method, password, timeout}, nil
}
