package trojan

import (
	"crypto/tls"
	"net"
	"time"
)

func Dial(network, address, hostPort, password string, config *tls.Config) (*tls.Conn, error) {
	conn, err := tls.Dial(network, address, config)
	if err != nil {
		return nil, err
	}
	if err = ClientHandshake(conn, hostPort, password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func DialTimeout(network, address, hostPort, password string, config *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	conn, err := tls.Dial(network, address, config)
	if err != nil {
		return nil, err
	}
	if err = ClientHandshakeTimeout(conn, hostPort, password, timeout); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type Listener struct {
	net.Listener
	auth    AuthMethod
	timeout time.Duration
}

// Accept 返回client请求的network,hostPort.
// err为trojan.AuthFailed时,[]byte(err.(trojan.AuthFailed))可以获取原始Bytes数据,进行重定向
func (l *Listener) Accept() (conn net.Conn, network, hostPort string, err error) {
	conn, err = l.Listener.Accept()
	if err != nil {
		return
	}
	network, hostPort, err = ServerHandshakeTimeout(conn, l.auth, l.timeout)
	return
}

func Listen(network, address string, auth AuthMethod, config *tls.Config) (*Listener, error) {
	l, err := tls.Listen(network, address, config)
	if err != nil {
		return nil, err
	}
	return &Listener{l, auth, 0}, nil
}

func ListenTimeout(network, address string, auth AuthMethod, config *tls.Config, timeout time.Duration) (*Listener, error) {
	l, err := tls.Listen(network, address, config)
	if err != nil {
		return nil, err
	}
	return &Listener{l, auth, timeout}, nil
}
