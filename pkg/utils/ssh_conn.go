package utils

import (
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

var ErrorInvalidConnection = errors.New("invalid connection")

type SshConn struct {
	dst io.ReadWriteCloser
}

func NewSshConn(conn ssh.Conn, remote string) (net.Conn, error) {
	if conn == nil {
		return nil, errors.New("the ssh connection is nil")
	}

	dst, reqs, err := conn.OpenChannel("kubesphere", []byte(remote))
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)

	return &SshConn{
		dst: dst,
	}, nil
}

func (s *SshConn) Read(b []byte) (n int, err error) {
	if s != nil {
		return s.dst.Read(b)
	}
	return 0, ErrorInvalidConnection
}

func (s *SshConn) Write(b []byte) (n int, err error) {
	if s != nil {
		return s.dst.Write(b)
	}

	return 0, ErrorInvalidConnection
}

func (s *SshConn) Close() error {
	if s != nil {
		return s.dst.Close()
	}
	return nil
}

func (s *SshConn) LocalAddr() net.Addr {
	return s
}

func (s *SshConn) RemoteAddr() net.Addr {
	return s
}

func (s *SshConn) SetDeadline(t time.Time) error {
	return nil
}

func (s *SshConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *SshConn) SetWriteDeadline(t time.Time) error {
	return nil // no-op
}

func (s *SshConn) Network() string {
	return "tcp"
}

func (s *SshConn) String() string {
	return ""
}
