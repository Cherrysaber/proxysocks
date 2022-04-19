package socks5

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func client(t *testing.T, wg *sync.WaitGroup, sleepTime time.Duration) {
	defer wg.Done()
	conn, err := net.Dial("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	// 手动 handshake
	// 避免 clientHandshake 有错误
	helloRequest := HelloRequest{Ver: Version, NMethods: 0x01, Methods: []byte{AuthMethodNone}}
	if err = helloRequest.FlushTo(conn); err != nil {
		t.Error(err)
		return
	}
	helloResponse := HelloResponse{}
	if err = helloResponse.ParseFrom(conn); err != nil {
		t.Error(err)
		return
	}
	if bytes.Index([]byte{AuthMethodNone}, []byte{helloResponse.Method}) == -1 {
		t.Error("helloResponse.Method should be MethodNone")
		return
	}

	host, port, err := net.SplitHostPort("127.0.0.1:6666")
	if err != nil {
		t.Error(err)
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Error(err)
		return
	}

	if sleepTime > 0 {
		time.Sleep(sleepTime)
		return
	}

	request := Request{
		Ver:      Version,
		Cmd:      CmdConnect,
		Rsv:      0x00,
		AddrType: AddrTypeDomain,
		DstAddr:  nil,
		DstPort:  nil,
	}
	request.DstAddr = append([]byte{byte(len(host))}, []byte(host)...)
	request.DstPort = make([]byte, 2, 2)

	binary.BigEndian.PutUint16(request.DstPort, uint16(p))
	if err = request.FlushTo(conn); err != nil {
		t.Error(err)
		return
	}

	response := Response{}
	if err = response.ParseFrom(conn); err != nil {
		t.Error(err)
		return
	}
}

func TestServerHandshake(t *testing.T) {
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := net.Listen("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go client(t, wg, 0)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hostPort, err := ServerHandshake(conn, []AuthMethod{NewAuthNone()})
	if err != nil {
		t.Fatal(err)
	}
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort, " != ", "127.0.0.1:6666")
	}
	response := Response{Ver: Version, Rep: 0x00, AddrType: AddrTypeIPv4,
		BndAddr: []byte{0x00, 0x00, 0x00, 0x00}, BndPort: []byte{0x00, 0x00}}
	if err = response.FlushTo(conn); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestServerHandshakeTimeout(t *testing.T) {
	testServerHandshakeTimeout(t)
	testServerHandshakeTimeoutError(t)
}

func testServerHandshakeTimeout(t *testing.T) {
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := net.Listen("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go client(t, wg, 0)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hostPort, err := ServerHandshakeTimeout(conn, []AuthMethod{NewAuthNone()}, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort, " != ", "127.0.0.1:6666")
	}
	response := Response{Ver: Version, Rep: 0x00, AddrType: AddrTypeIPv4,
		BndAddr: []byte{0x00, 0x00, 0x00, 0x00}, BndPort: []byte{0x00, 0x00}}
	if err = response.FlushTo(conn); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func testServerHandshakeTimeoutError(t *testing.T) {
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := net.Listen("tcp", "127.0.0.1:23333")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go client(t, wg, 100*time.Millisecond)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = ServerHandshakeTimeout(conn, []AuthMethod{NewAuthNone()}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("should be timeout")
	}

	type wrapError interface {
		Error() string
		Unwrap() error
	}
	err = err.(wrapError).Unwrap()

	if err, ok := err.(*net.OpError); !ok {
		t.Fatal("should be timeout")
	} else if !err.Timeout() {
		t.Fatal("should be timeout not ", err)
	}
	wg.Wait()

}
