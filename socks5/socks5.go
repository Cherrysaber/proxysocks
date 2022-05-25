// Copyright (c) 2022 Cherrysaber. All rights reserved.

// Package socks5
//
// SOCKS protocol version 5 is defined in RFC 1928.
// Username/Password authentication for SOCKS version 5 is defined in
// RFC 1929.
package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

// s5Error is the error type usually returned by functions in the socks5
// package. It describes the prefix, operation of an error.
type s5Error struct {
	prefix string
	op     string
	err    error
}

func (e *s5Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := e.prefix
	if e.op != "" {
		s += " " + e.op
	}
	if e.err != nil {
		s += ": " + e.err.Error()
	}
	return s
}

func (e *s5Error) Unwrap() error {
	return e.err
}

const (
	Version = 0x05 // SOCKS Protocol version 5

	AuthMethodNone                = 0x00 // No authentication required
	AuthMethodGSSAPI              = 0x01 // GSSAPI
	AuthMethodUserPassword        = 0x02 // Username/Password
	AuthMethodNoAcceptableMethods = 0xFF // No acceptable method

	AddrTypeIPv4   = 0x01 // 1 for IPv4 address
	AddrTypeDomain = 0x03 // 3 for domain name
	AddrTypeIPv6   = 0x04 // 4 for IPv6 address

	CmdConnect      = 0x01 // establish a TCP/IP stream connection
	CmdBind         = 0x02 // associate a name with a socket todo
	CmdUdpAssociate = 0x03 // establish a UDP association todo

	StatusSucceeded = 0x00 // succeeded
)

// A ReplyCode represents a SOCKS command reply code.
type ReplyCode int

func (code ReplyCode) String() string {
	switch code {
	case StatusSucceeded:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown code: " + strconv.Itoa(int(code))
	}
}

// bugfix: 兼容其他语言编写的socks5
// w.Write([]byte{Ver, hr.NMethods})
// w.Write(hr.Methods)
// 如果其他语言编写的 socks5 没有类似 io.ReadFull 的函数,可能会导致无法读全，抛出错误
// 所以先把要发送的 byte 配置完成后再发送

/*
	+----+----------+----------+
	|Ver | NMethods | Methods  |
	+----+----------+----------+
	| 1  |    1     | 1 to 255 |
	+----+----------+----------+
*/

// HelloRequest is the hello request packet
type HelloRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1-255 bytes
}

func (hr *HelloRequest) Size() int {
	return 2 + len(hr.Methods)
}

func (hr *HelloRequest) ParseFrom(r io.Reader) error {
	buf := make([]byte, 2, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return &s5Error{
			prefix: "HelloRequest",
			op:     "Read Ver and NMethods",
			err:    err,
		}
	}

	if buf[0] != Version {
		return &s5Error{
			prefix: "HelloRequest",
			err:    errors.New("invalid version " + strconv.Itoa(int(buf[0]))),
		}
	}

	if buf[1] == 0x00 {
		return &s5Error{
			prefix: "HelloRequest",
			err:    errors.New("invalid NMethods"),
		}
	}

	hr.Ver, hr.NMethods = buf[0], buf[1]
	buf = make([]byte, hr.NMethods, hr.NMethods)
	if _, err := io.ReadFull(r, buf); err != nil {
		return &s5Error{
			prefix: "HelloRequest",
			op:     "Read Methods",
			err:    err,
		}
	}
	hr.Methods = buf
	return nil
}

func (hr *HelloRequest) FlushTo(w io.Writer) error {
	buf := append([]byte{hr.Ver, hr.NMethods}, hr.Methods...)
	if _, err := w.Write(buf); err != nil {
		return &s5Error{
			prefix: "HelloRequest",
			op:     "Flush to Writer",
			err:    err,
		}
	}
	return nil
}

/*
	+----+----------+
	|Ver | Method   |
	+----+----------+
	| 1  |   1      |
	+----+----------+
*/

type HelloResponse struct {
	Ver    byte
	Method byte
}

func (hr *HelloResponse) Size() int {
	return 2
}

func (hr *HelloResponse) ParseFrom(r io.Reader) error {
	buf := make([]byte, 2, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return &s5Error{
			prefix: "HelloResponse",
			op:     "Read Ver and Method",
			err:    err,
		}
	}

	if buf[0] != Version {
		return &s5Error{
			prefix: "HelloResponse",
			err:    errors.New("invalid version " + strconv.Itoa(int(buf[0]))),
		}
	}

	if buf[1] == AuthMethodNoAcceptableMethods {
		return &s5Error{
			prefix: "HelloResponse",
			err:    errors.New("no acceptable authentication methods"),
		}
	}

	hr.Ver, hr.Method = buf[0], buf[1]
	return nil
}

func (hr *HelloResponse) FlushTo(w io.Writer) error {
	buf := []byte{hr.Ver, hr.Method}
	if _, err := w.Write(buf); err != nil {
		return &s5Error{
			prefix: "HelloResponse",
			op:     "Flush to Writer",
			err:    err,
		}
	}
	return nil
}

/*
	+----+-----+-------+------+----------+----------+
	|Ver | Cmd |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | 0x00  |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
*/

// Request is the request packet
type Request struct {
	Ver      byte
	Cmd      byte
	Rsv      byte // 0x00
	AddrType byte
	DstAddr  []byte
	DstPort  []byte // 2 bytes
}

func (req *Request) Size() int {
	return 4 + len(req.DstAddr) + len(req.DstPort)
}

func (req *Request) ParseFrom(r io.Reader) error {
	buf := make([]byte, 4, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return &s5Error{
			prefix: "Request",
			op:     "Read Ver, Cmd, Rsv, AddrType",
			err:    err,
		}
	}

	if buf[0] != Version {
		return &s5Error{
			prefix: "Request",
			err:    errors.New("invalid version " + strconv.Itoa(int(buf[0]))),
		}
	}

	switch buf[1] {
	case CmdConnect:
	case CmdBind:
	case CmdUdpAssociate:
		// match break
	default: // return err
		return &s5Error{
			prefix: "Request",
			err:    errors.New("invalid command " + strconv.Itoa(int(buf[1]))),
		}

	}

	req.Ver, req.Cmd, req.Rsv, req.AddrType = buf[0], buf[1], buf[2], buf[3]

	switch buf[3] {
	case AddrTypeIPv4:
		req.DstAddr = make([]byte, 4, 4)
		buf = req.DstAddr
	case AddrTypeDomain:
		if _, err := r.Read(buf[0:1]); err != nil {
			return &s5Error{
				prefix: "Request",
				op:     "Read Addr Length",
				err:    err,
			}
		}
		if buf[0] == 0x00 {
			return &s5Error{
				prefix: "Request",
				err:    errors.New("invalid length"),
			}
		}
		req.DstAddr = make([]byte, 1+buf[0], 1+buf[0])
		req.DstAddr[0], buf = buf[0], req.DstAddr[1:]
	case AddrTypeIPv6:
		req.DstAddr = make([]byte, 16, 16)
		buf = req.DstAddr
	default:
		return &s5Error{
			prefix: "Request",
			err:    errors.New("invalid address type " + strconv.Itoa(int(buf[3]))),
		}

	}

	if _, err := io.ReadFull(r, buf); err != nil {
		return &s5Error{
			prefix: "Request",
			op:     "Read Addr Bytes",
			err:    err,
		}
	}

	req.DstPort = make([]byte, 2)
	if _, err := io.ReadFull(r, req.DstPort); err != nil {
		return &s5Error{
			prefix: "Request",
			op:     "Read Port Bytes",
			err:    err,
		}
	}

	return nil
}

func (req *Request) FlushTo(w io.Writer) error {
	buf := append([]byte{req.Ver, req.Cmd, req.Rsv, req.AddrType}, req.DstAddr...)
	buf = append(buf, req.DstPort...)
	if _, err := w.Write(buf); err != nil {
		return &s5Error{
			prefix: "Request",
			op:     "Flush to Writer",
			err:    err,
		}
	}
	return nil
}

/*
	+----+-----+-------+------+----------+----------+
	|Ver | Rep |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | 0x00  |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
*/

type Response struct {
	Ver      byte
	Rep      byte
	Rsv      byte // 0x00
	AddrType byte
	BndAddr  []byte
	BndPort  []byte // 2 bytes
}

func (res *Response) Size() int {
	return 4 + len(res.BndAddr) + len(res.BndPort)
}

func (res *Response) ParseFrom(r io.Reader) error {
	buf := make([]byte, 4, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return &s5Error{
			prefix: "Response",
			op:     "Read Ver, Rep, Rsv, AddrType",
			err:    err,
		}
	}

	if buf[0] != Version {
		return &s5Error{
			prefix: "Response",
			err:    errors.New("invalid version " + strconv.Itoa(int(buf[0]))),
		}
	}

	if buf[1] != StatusSucceeded {
		return &s5Error{
			prefix: "Response",
			err:    errors.New(ReplyCode(buf[1]).String()),
		}
	}

	res.Ver, res.Rep, res.Rsv, res.AddrType = buf[0], buf[1], buf[2], buf[3]

	switch buf[3] {
	case AddrTypeIPv4:
		res.BndAddr = make([]byte, 4, 4)
		buf = res.BndAddr
	case AddrTypeDomain:
		if _, err := r.Read(buf[0:1]); err != nil {
			return &s5Error{
				prefix: "Response",
				op:     "Read Addr Length",
				err:    err,
			}
		}
		if buf[0] == 0x00 {
			return &s5Error{
				prefix: "Response",
				err:    errors.New("invalid length"),
			}
		}
		res.BndAddr = make([]byte, 1+buf[0], 1+buf[0])
		res.BndAddr[0], buf = buf[0], res.BndAddr[1:]
	case AddrTypeIPv6:
		res.BndAddr = make([]byte, 16, 16)
		buf = res.BndAddr
	default:
		return &s5Error{
			prefix: "Response",
			err:    errors.New("invalid address type " + strconv.Itoa(int(buf[3]))),
		}

	}

	if _, err := io.ReadFull(r, buf); err != nil {
		return &s5Error{
			prefix: "Response",
			op:     "Read Addr Bytes",
			err:    err,
		}
	}

	res.BndPort = make([]byte, 2)
	if _, err := io.ReadFull(r, res.BndPort); err != nil {
		return &s5Error{
			prefix: "Response",
			op:     "Read Port Bytes",
			err:    err,
		}
	}

	return nil
}

func (res *Response) FlushTo(w io.Writer) error {
	buf := append([]byte{res.Ver, res.Rep, res.Rsv, res.AddrType}, res.BndAddr...)
	buf = append(buf, res.BndPort...)
	if _, err := w.Write(buf); err != nil {
		return &s5Error{
			prefix: "Response",
			op:     "Flush to Writer",
			err:    err,
		}
	}
	return nil
}

// ParseHostPort 通过addrType解析addr和port,转换为host:port格式
func ParseHostPort(addrType byte, addr []byte, port []byte) (hostPort string, err error) {
	p := binary.BigEndian.Uint16(port)
	switch addrType {
	case AddrTypeIPv4, AddrTypeIPv6:
		hostPort = net.IP(addr).String() + ":" + strconv.Itoa(int(p))
	case AddrTypeDomain:
		hostPort = string(addr[1:]) + ":" + strconv.Itoa(int(p))
	default:
		err = errors.New("invalid address type " + strconv.Itoa(int(addrType)))
	}
	return
}
