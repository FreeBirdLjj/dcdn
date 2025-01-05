package tcp

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

func sniffHTTPHost(rc io.Reader) (host string, err error) {
	req, err := http.ReadRequest(bufio.NewReader(rc))
	if err != nil {
		return "", err
	}
	return req.Host, nil
}

func ForwardHTTP(clientConn *net.TCPConn) {
	SniffHostAndForward(sniffHTTPHost, clientConn)
}
