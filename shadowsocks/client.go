package shadowsocks

import (
	"io"
	"net"
	"strconv"
	"time"
)

func ClientHandshake(conn net.Conn, hostPort string) error {
	return clientHandshake(conn, hostPort)
}

func ClientHandshakeTimeout(conn net.Conn, hostPort string, timeout time.Duration) error {
	if timeout > 0 {
		// set timeout
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return &ssError{
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
	return clientHandshake(conn, hostPort)
}

func clientHandshake(rw io.ReadWriter, hostPort string) error {
	// hostPort to bytes
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return &ssError{
			prefix: "clientHandshake",
			op:     "SplitHostPort",
			err:    err,
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return &ssError{
			prefix: "clientHandshake",
			err:    err,
		}
	}

	// AddrTypeDomain 0x03
	buf := append([]byte{0x03, byte(len(host))}, []byte(host)...)
	buf = append(buf, byte(p>>8), byte(p))
	if _, err = rw.Write(buf); err != nil {
		return &ssError{
			prefix: "clientHandshake",
			op:     "Write HostPort",
			err:    err,
		}
	}
	return nil
}
