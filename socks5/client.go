// Copyright (c) 2022 Cherrysaber. All rights reserved.

package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

// ClientHandshake client执行socks5握手,
func ClientHandshake(conn net.Conn, hostPort string, cmd byte, auths []AuthMethod) error {
	return clientHandshake(conn, hostPort, cmd, auths)
}

// ClientHandshakeTimeout client设置超时时间并执行socks5握手
func ClientHandshakeTimeout(conn net.Conn, hostPort string, cmd byte, auths []AuthMethod, timeout time.Duration) error {
	if timeout > 0 {
		// set timeout
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return &s5Error{
				prefix: "clientHandshake",
				op:     "SetDeadline",
				err:    err,
			}
		}

		// reset
		defer func() {
			if err := conn.SetDeadline(time.Time{}); err != nil {
				panic(err)
			}
		}()
	}

	return clientHandshake(conn, hostPort, cmd, auths)
}

// 握手开始
// client send hello request
// client receive hello response
// client select auth method and use it
// client send request
// client receive response
// 握手结束
func clientHandshake(rw io.ReadWriter, hostPort string, cmd byte, auths []AuthMethod) error {
	// client support auth methods
	ms := make([]byte, len(auths), len(auths))
	for i := range auths {
		ms[i] = auths[i].Method()
	}
	// client send hello request
	helloRequest := HelloRequest{Version, byte(len(ms)), ms}
	if err := helloRequest.FlushTo(rw); err != nil {
		return err
	}
	// client receive hello reply
	helloResponse := HelloResponse{}
	if err := helloResponse.ParseFrom(rw); err != nil {
		return err
	}
	i := bytes.Index(ms, []byte{helloResponse.Method})
	// 如果 i == -1 在 helloResponse.ParseFrom 已经抛出错误了
	// 这时 i 不应为 -1
	if i == -1 {
		panic("clientHandshake: helloResponse.Method not found in auths")
	}

	// Auth
	if err := auths[i].Auth(rw); err != nil {
		return err
	}

	// hostPort to bytes, make request
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return &s5Error{
			prefix: "clientHandshake",
			op:     "HostPortToBytes",
			err:    err,
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return &s5Error{
			prefix: "clientHandshake",
			op:     "HostPortToBytes",
			err:    err,
		}
	}

	request := Request{
		Ver:      Version,
		Cmd:      cmd,
		Rsv:      0x00,
		AddrType: AddrTypeDomain,
		DstAddr:  nil,
		DstPort:  nil,
	}
	request.DstAddr = append([]byte{byte(len(host))}, []byte(host)...)
	request.DstPort = make([]byte, 2, 2)

	binary.BigEndian.PutUint16(request.DstPort, uint16(p))
	// client send request
	if err = request.FlushTo(rw); err != nil {
		return err
	}
	// client receive reply
	response := Response{}
	err = response.ParseFrom(rw)
	return err
}
