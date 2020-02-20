package proxy

import "net/http/httputil"

type Server struct {
	httpServer   *HTTPServer
	reverseProxy *httputil.ReverseProxy
	sessCount    int32
	sessions
}
