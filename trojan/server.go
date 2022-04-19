package trojan

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

func ServerHandshake(conn net.Conn, auth AuthMethod) (network string, hostPort string, err error) {
	return serverHandshake(conn, auth)
}

func ServerHandshakeTimeout(conn net.Conn, auth AuthMethod, timeout time.Duration) (network string, hostPort string, err error) {
	if timeout > 0 {
		// set timeout
		if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return
		}

		// reset
		defer func() {
			if e := conn.SetDeadline(time.Time{}); e != nil {
				panic(e)
			}
		}()
	}
	return serverHandshake(conn, auth)
}

// 只有在56位hash没有读满或者验证失败时返回AuthFailure,
// []byte(err)得到原始Bytes流,可以进行重定向
func serverHandshake(rw io.ReadWriter, auth AuthMethod) (network string, hostPort string, err error) {
	buf := make([]byte, 56, 56)
	if n, err := io.ReadFull(rw, buf); err != nil {
		if n != 0 {
			err = AuthFailure(buf[:n])
		}
		return "", "", err
	}

	// 验证
	if !auth.Auth(string(buf)) {
		err = AuthFailure(buf)
		return
	}

	// discard crlf
	if _, err = io.ReadFull(rw, buf[:2]); err != nil {
		err = &tjError{
			prefix: "serverHandshake",
			op:     "Discard crlf",
			err:    err,
		}
		return
	}

	// parse request

	// read cmd addrType
	if _, err = io.ReadFull(rw, buf[:2]); err != nil {
		err = &tjError{
			prefix: "serverHandshake",
			op:     "Read Cmd and AddrType",
			err:    err,
		}
		return
	}

	// 0x03 udp todo
	switch buf[0] {
	case 0x01:
		network = "tcp"
	case 0x03:
		network = "udp"
	default:
		err = &tjError{
			prefix: "serverHandshake",
			err:    errors.New("unknown cmd " + string(buf[0])),
		}
		return
	}

	switch buf[1] {
	case 0x01: // AddrTypeIPv4
		buf = make([]byte, 4, 4)
		if _, err = io.ReadFull(rw, buf); err != nil {
			err = &tjError{
				prefix: "serverHandshake",
				op:     "Read IPv4 Bytes",
				err:    err,
			}
			return
		}
		hostPort = net.IP(buf).String()
	case 0x03: // AddrTypeDomain
		if _, err = rw.Read(buf[:1]); err != nil {
			err = &tjError{
				prefix: "serverHandshake",
				op:     "Read Addr Length",
				err:    err,
			}
			return
		}
		if buf[0] == 0x00 {
			err = &tjError{
				prefix: "serverHandshake",
				err:    errors.New("invalid Addr Length"),
			}
			return
		}
		buf = make([]byte, buf[0], buf[0])
		if _, err = io.ReadFull(rw, buf); err != nil {
			err = &tjError{
				prefix: "serverHandshake",
				op:     "Read Domain Bytes",
				err:    err,
			}
			return
		}
		hostPort = string(buf)
	case 0x04: // AddrTypeIPv6
		buf = make([]byte, 16, 16)
		if _, err = io.ReadFull(rw, buf); err != nil {
			err = &tjError{
				prefix: "serverHandshake",
				op:     "Read IPv6 Bytes",
				err:    err,
			}
			return
		}
		hostPort = net.IP(buf).String()
	default:
		err = &tjError{
			prefix: "serverHandshake",
			err:    errors.New("invalid AddrType " + strconv.Itoa(int(buf[0]))),
		}
		return
	}
	buf = make([]byte, 2, 2)
	if _, err = io.ReadFull(rw, buf); err != nil {
		err = &tjError{
			prefix: "serverHandshake",
			op:     "Read Port Bytes",
			err:    err,
		}
		return
	}
	port := binary.BigEndian.Uint16(buf)
	hostPort += ":" + strconv.Itoa(int(port))

	// parse request

	// discard crlf
	if _, err = io.ReadFull(rw, buf[:2]); err != nil {
		err = &tjError{
			prefix: "serverHandshake",
			op:     "Discard crlf",
			err:    err,
		}
	}
	return
}
