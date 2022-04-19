package shadowsocks

import (
	"net"
	"sync"
	"testing"
	"time"
)

var serverLock = &sync.Mutex{}

func server(t *testing.T, wg *sync.WaitGroup, sleepTime time.Duration) {
	serverLock.Lock()
	defer serverLock.Unlock()
	defer wg.Done()

	// 防止map同时读写错误
	cryptor, err := NewCipher("aes-128-gcm", "password")
	if err != nil {
		t.Error(err)
		return
	}

	ln, err := net.Listen("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Error(err)
		return
	}
	defer ln.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	if sleepTime > 0 {
		time.Sleep(sleepTime)
		return
	}

	// 手动操作
	ss := &Conn{
		Conn:    conn,
		cryptor: cryptor,
	}

	hostPort, err := serverHandshake(ss)
	if err != nil {
		t.Error(err)
		return
	}
	if hostPort != "127.0.0.1:6666" {
		t.Error(hostPort + " != 127.0.0.1:6666")
		return
	}
}

func TestClientHandshake(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 0)
	time.Sleep(time.Millisecond * 100)
	conn, err := net.Dial("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	cryptor, err := NewCipher("aes-128-gcm", "password")
	if err != nil {
		t.Fatal(err)
	}
	ss := &Conn{
		Conn:    conn,
		cryptor: cryptor,
	}
	err = ClientHandshake(ss, "127.0.0.1:6666")
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()

}

func TestClientHandshakeTimeout(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 0)
	time.Sleep(time.Millisecond * 100)
	conn, err := net.Dial("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	cryptor, err := NewCipher("aes-128-gcm", "password")
	if err != nil {
		t.Fatal(err)
	}
	ss := &Conn{
		Conn:    conn,
		cryptor: cryptor,
	}
	err = ClientHandshakeTimeout(ss, "127.0.0.1:6666", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()

}
