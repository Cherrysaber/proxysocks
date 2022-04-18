package socks5

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDial(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 0)
	conn, err := Dial("tcp", "127.0.0.1:23333", "127.0.0.1:6666",
		[]AuthMethod{NewAuthNone()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wg.Wait()
}

func TestDialTimeout(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go server(t, wg, 5*time.Second)
	_, err := DialTimeout("tcp", "127.0.0.1:23333", "127.0.0.1:6666",
		[]AuthMethod{NewAuthNone()}, 2*time.Second)
	if err == nil {
		t.Fatal("should be timeout")
	}
	err = err.(wrapError).Unwrap()
	if err, ok := err.(*net.OpError); !ok {
		t.Fatal("should be timeout")
	} else if !err.Timeout() {
		t.Fatal("should be timeout not ", err)
	}
	wg.Wait()
}

func TestListen(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := Listen("tcp", "127.0.0.1:23333",
		[]AuthMethod{NewAuthNone()})
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
		t.Fatal(hostPort, " != ", "127.0.0.1:6666")
	}
	wg.Wait()
}

func TestListenTimeout(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := ListenTimeout("tcp", "127.0.0.1:23333",
		[]AuthMethod{NewAuthNone()}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go client(t, wg, 5*time.Second)
	_, _, err = ln.Accept()
	if err == nil {
		t.Fatal("should be timeout")
	}
	err = err.(wrapError).Unwrap()
	if err, ok := err.(*net.OpError); !ok {
		t.Fatal("should be timeout")
	} else if !err.Timeout() {
		t.Fatal("should be timeout not ", err)
	}
	wg.Wait()

}

func responseCreate(address string, err error) *Response {
	response := &Response{
		Ver:      Version,
		Rep:      0x01,
		Rsv:      0x00,
		AddrType: AddrTypeIPv4,
		BndAddr:  []byte{0, 0, 0, 0},
		BndPort:  []byte{0, 0},
	}
	return response
	/*
		err = err.(wrapError).Unwrap()
		switch err.Error() {
		case "general SOCKS server failure":
			response.Rep = 0x01
		case "connection not allowed by ruleset":
			response.Rep = 0x02
		case "network unreachable":
			response.Rep = 0x03
		case "host unreachable":
			response.Rep = 0x04
		case "connection refused":
			response.Rep = 0x05
		case "TTL expired":
			response.Rep = 0x06
		case "command not supported":
			response.Rep = 0x07
		case "address type not supported":
			response.Rep = 0x08
		default:
			panic(err)
		}
		return response
	*/
}

func TestAcceptResponse(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	serverLock.Lock()
	defer serverLock.Unlock()
	ln, err := Listen("tcp", "127.0.0.1:23333",
		[]AuthMethod{NewAuthNone()})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Second)
		conn, err := Dial("tcp", "127.0.0.1:23333", "127.0.0.1:6666", nil)
		if err == nil {
			conn.Close()
			t.Error("should be Response Error")
			return
		}
		targetErr := &s5Error{
			prefix: "Response",
			err:    errors.New(ReplyCode(1).String()),
		}
		if targetErr.Error() != err.Error() {
			t.Error("error should be ", targetErr.Error(), " not ", err.Error())
			return
		}
	}()

	conn, hostPort, err := ln.AcceptResponse(responseCreate)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if hostPort != "127.0.0.1:6666" {
		t.Fatal(hostPort, " != ", "127.0.0.1:6666")
	}
	wg.Wait()
}
