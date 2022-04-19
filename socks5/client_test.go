package socks5

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

func TestClientHandshake(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 0)
	conn, err := net.Dial("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = ClientHandshake(conn, "127.0.0.1:6666", CmdConnect, []AuthMethod{NewAuthNone()})
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestClientHandshakeTimeout(t *testing.T) {
	testClientHandshakeTimeout(t)
	testClientHandshakeTimeoutError(t)
}

func testClientHandshakeTimeout(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 0)
	conn, err := net.Dial("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = ClientHandshakeTimeout(conn, "127.0.0.1:6666", CmdConnect,
		[]AuthMethod{NewAuthNone()}, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func testClientHandshakeTimeoutError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 100*time.Millisecond)
	conn, err := net.Dial("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = ClientHandshakeTimeout(conn, "127.0.0.1:6666",
		CmdConnect, []AuthMethod{NewAuthNone()}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("should be timeout")
	}
	type wrapError interface {
		Error() string
		Unwrap() error
	}
	err = err.(wrapError).Unwrap()
	if err, ok := err.(*net.OpError); !ok {
		t.Fatal("should be timeout not ", err)
	} else if !err.Timeout() {
		t.Fatal("should be timeout not ", err)
	}
	wg.Wait()
}

var serverLock = &sync.Mutex{}

func server(t *testing.T, wg *sync.WaitGroup, sleepTime time.Duration) {
	serverLock.Lock()
	defer serverLock.Unlock()
	defer wg.Done()
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

	// 手动 socks5 handshake
	// 避免 ServerHandshake 有错误
	helloRequest := HelloRequest{}
	if err = helloRequest.ParseFrom(conn); err != nil {
		t.Error(err)
		return
	}
	helloResponse := HelloResponse{Ver: Version, Method: AuthMethodNone}
	if bytes.Index(helloRequest.Methods, []byte{0x00}) == -1 {
		t.Error("Auth method should be 0x00")
		return
	}
	if err = helloResponse.FlushTo(conn); err != nil {
		t.Error(err)
		return
	}

	if sleepTime > 0 {
		time.Sleep(sleepTime)
		return
	}

	request := Request{}
	if err = request.ParseFrom(conn); err != nil {
		t.Error(err)
		return
	}

	response := Response{Ver: Version, Rep: 0x00, AddrType: AddrTypeIPv4,
		BndAddr: []byte{0x00, 0x00, 0x00, 0x00}, BndPort: []byte{0x00, 0x00}}
	if err = response.FlushTo(conn); err != nil {
		t.Error(err)
		return
	}
	hostPort, err := ParseHostPort(request.AddrType, request.DstAddr, request.DstPort)
	if err != nil {
		t.Error(err)
		return
	}
	if hostPort != "127.0.0.1:6666" {
		t.Error(hostPort, " != ", "127.0.0.1:6666")
	}
	return
}
