package utils

import (
	"io"
	"net"

	"k8s.io/klog/v2"
)

func HandleTCPStream(src io.ReadWriteCloser, remote string) {
	dst, err := net.Dial("tcp", remote)
	if err != nil {
		klog.Error("remote failed", err)
		src.Close()
		return
	}
	s, r := Pipe(src, dst)
	klog.V(2).Infof("sent %d, received %d", s, r)
}
