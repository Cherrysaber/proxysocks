package shadowsocks

import (
	"net"
	"sync"
	"testing"
	"time"
)

func client(t *testing.T, wg *sync.WaitGroup, sleepTime time.Duration) {
	defer wg.Done()
	time.Sleep(100 * time.Millisecond)
	conn, err := net.Dial("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	// 手动操作
	cryptor, err := NewCipher("aes-128-gcm", "password")
	if err != nil {
		t.Error(err)
		return
	}
	ss := &Conn{
		Conn:    conn,
		cryptor: cryptor,
	}

	if sleepTime > 0 {
		time.Sleep(sleepTime)
		return
	}

	err = clientHandshake(ss, "127.0.0.1:6666")
	if err != nil {
		t.Error(err)
		return
	}

}

func TestServerHandshake(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	cryptor, err := NewCipher("aes-128-gcm", "password")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go client(t, wg, 0)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ss := &Conn{
		Conn:    conn,
		cryptor: cryptor,
	}
	hostPort, err := ServerHandshake(ss)
	if err != nil {
		t.Fatal(err)
	}
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort + " != 127.0.0.1:6666")
	}
	wg.Wait()
}

func TestServerHandshakeTimeout(t *testing.T) {
	testServerHandshakeTimeout(t)
	testServerHandshakeTimeoutError(t)
}

func testServerHandshakeTimeout(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	cryptor, err := NewCipher("aes-128-gcm", "password")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go client(t, wg, 0)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ss := &Conn{
		Conn:    conn,
		cryptor: cryptor,
	}
	hostPort, err := ServerHandshakeTimeout(ss, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort + " != 127.0.0.1:6666")
	}
	wg.Wait()
}

func testServerHandshakeTimeoutError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	cryptor, err := NewCipher("aes-128-gcm", "password")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go client(t, wg, 100*time.Millisecond)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ss := &Conn{
		Conn:    conn,
		cryptor: cryptor,
	}
	_, err = ServerHandshakeTimeout(ss, 50*time.Millisecond)
	type wrapError interface {
		Error() string
		Unwrap() error
	}
	defer wg.Wait()
	for err != nil {
		err = err.(wrapError).Unwrap()
		if err, ok := err.(*net.OpError); ok && err.Timeout() {
			return
		}
	}
	t.Fatal("should be timeout not ", err)
}
