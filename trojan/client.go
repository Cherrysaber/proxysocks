package trojan

import (
	"io"
	"net"
	"strconv"
	"time"
)

func ClientHandshake(conn net.Conn, hostPort, password string) error {
	return clientHandshake(conn, hostPort, password)
}

func ClientHandshakeTimeout(conn net.Conn, hostPort, password string, timeout time.Duration) error {
	if timeout > 0 {
		// set timeout
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return &tjError{
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
	return clientHandshake(conn, hostPort, password)
}

func clientHandshake(rw io.ReadWriter, hostPort, password string) error {
	hash := sha224(password)

	// hostPort to bytes
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return &tjError{
			prefix: "clientHandshake",
			op:     "SplitHostPort",
			err:    err,
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return &tjError{
			prefix: "clientHandshake",
			err:    err,
		}
	}

	// crlf socks5.CmdConnect socks5.AddrTypeDomain host port crlf
	buf := append([]byte(crlf), []byte{0x01, 0x03, byte(len(host))}...)
	buf = append(buf, []byte(host)...)
	buf = append(buf, byte(p>>8), byte(p))
	buf = append(buf, []byte(crlf)...)

	if _, err = rw.Write(hash); err != nil {
		return &tjError{
			prefix: "clientHandshake",
			op:     "Write hash Bytes",
			err:    err,
		}
	}

	if _, err = rw.Write(buf); err != nil {
		return &tjError{
			prefix: "clientHandshake",
			op:     "Write Request Bytes",
			err:    err,
		}
	}
	return nil
}
