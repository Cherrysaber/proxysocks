package shadowsocks

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

func ServerHandshake(conn net.Conn) (hostPort string, err error) {
	return serverHandshake(conn)
}

func ServerHandshakeTimeout(conn net.Conn, timeout time.Duration) (hostPort string, err error) {
	if timeout > 0 {
		// set timeout
		if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			err = &ssError{
				prefix: "serverHandshake",
				op:     "SetDeadline",
				err:    err,
			}
			return
		}

		// reset
		defer func() {
			if e := conn.SetDeadline(time.Time{}); e != nil {
				panic(e)
			}
		}()
	}
	return serverHandshake(conn)
}

func serverHandshake(rw io.ReadWriter) (hostPort string, err error) {
	buf := make([]byte, 1)
	if _, err = rw.Read(buf); err != nil {
		err = &ssError{
			prefix: "serverHandshake",
			op:     "Read AddrType",
			err:    err,
		}
		return
	}

	switch buf[0] {
	case 0x01: // AddrTypeIPv4
		buf = make([]byte, 4, 4)
		if _, err = io.ReadFull(rw, buf); err != nil {
			err = &ssError{
				prefix: "serverHandshake",
				op:     "Read IPv4 Bytes",
				err:    err,
			}
			return
		}
		hostPort = net.IP(buf).String()
	case 0x03: // AddrTypeDomain
		if _, err = rw.Read(buf); err != nil {
			err = &ssError{
				prefix: "serverHandshake",
				op:     "Read Addr Length",
				err:    err,
			}
			return
		}
		if buf[0] == 0x00 {
			err = &ssError{
				prefix: "serverHandshake",
				err:    errors.New("invalid Addr Length"),
			}
			return
		}
		buf = make([]byte, buf[0], buf[0])
		if _, err = io.ReadFull(rw, buf); err != nil {
			err = &ssError{
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
			err = &ssError{
				prefix: "serverHandshake",
				op:     "Read IPv6 Bytes",
				err:    err,
			}
			return
		}
		hostPort = net.IP(buf).String()
	default:
		err = &ssError{
			prefix: "serverHandshake",
			err:    errors.New("invalid AddrType " + strconv.Itoa(int(buf[0]))),
		}
		return
	}
	buf = make([]byte, 2, 2)
	if _, err = io.ReadFull(rw, buf); err != nil {
		err = &ssError{
			prefix: "serverHandshake",
			op:     "Read Port Bytes",
			err:    err,
		}
		return
	}
	port := binary.BigEndian.Uint16(buf)
	hostPort += ":" + strconv.Itoa(int(port))
	return
}
