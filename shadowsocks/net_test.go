package shadowsocks

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestDial(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 0)
	time.Sleep(100 * time.Millisecond)
	conn, err := Dial("tcp", "127.0.0.1:23333", "127.0.0.1:6666",
		"aes-128-gcm", "password")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wg.Wait()
}

func TestDialTimeout(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 0)
	time.Sleep(100 * time.Millisecond)
	conn, err := DialTimeout("tcp", "127.0.0.1:23333", "127.0.0.1:6666",
		"aes-128-gcm", "password", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wg.Wait()
}

func TestListen(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := Listen("tcp", "127.0.0.1:23333", "aes-128-gcm", "password")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go client(t, wg, 0)
	conn, hostPort, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort + " != 127.0.0.1:6666")
	}
	wg.Wait()
}

func TestListenTimeout(t *testing.T) {
	testListenTimeout(t)
	testListenTimeoutError(t)
}

func testListenTimeout(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := ListenTimeout("tcp", "127.0.0.1:23333", "aes-128-gcm",
		"password", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go client(t, wg, 0)
	conn, hostPort, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort + " != 127.0.0.1:6666")
	}
	wg.Wait()
}

func testListenTimeoutError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := ListenTimeout("tcp", "127.0.0.1:23333", "aes-128-gcm",
		"password", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go client(t, wg, 100*time.Millisecond)
	conn, _, err := ln.Accept()
	if conn != nil {
		defer conn.Close()
	}
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
