package utils

import (
	"errors"
	"k8s.io/klog"
	"net/url"
	"strconv"
	"strings"
)

// Remote represents address forwarding, format like following
// LocalHost:LocalPort:RemoteHost:RemotePort
type Remote struct {
	LocalHost, LocalPort, RemoteHost, RemotePort string
}

var ErrInvalidRemoteFormat = errors.New("invalid remote, should be format like LocalHost:LocalPort:RemoteHost:RemotePort")
var ErrInvalidRemoteValue = errors.New("invalid port number or host")

func DecodeRemote(s string) (*Remote, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		klog.Errorln(s, ErrInvalidRemoteFormat)
		return nil, ErrInvalidRemoteFormat
	}

	if !isHost(parts[0]) || !isPort(parts[1]) || !isHost(parts[2]) || !isPort(parts[3]) {
		klog.Error(ErrInvalidRemoteValue)
		return nil, ErrInvalidRemoteValue
	}
	return &Remote{
		LocalHost:  parts[0],
		LocalPort:  parts[1],
		RemoteHost: parts[2],
		RemotePort: parts[3],
	}, nil
}

func isPort(s string) bool {
	port, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	if port > 65535 || port <= 0 {
		klog.Error("invalid port", port)
		return false
	}
	return true
}

func isHost(s string) bool {
	_, err := url.Parse(s)
	if err != nil {
		return false
	}
	return true
}

func (r *Remote) Remote() string {
	return r.RemoteHost + ":" + r.RemotePort
}

func (r *Remote) Local() string {
	return r.LocalHost + ":" + r.LocalPort
}
