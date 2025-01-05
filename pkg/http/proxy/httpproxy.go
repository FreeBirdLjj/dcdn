package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	nurl "net/url"

	"golang.org/x/net/proxy"
)

type (
	dialer struct {
		proxyURL  *nurl.URL
		proxyDial func(ctx context.Context, network string, address string) (c net.Conn, err error)

		// testing fields
		rootCAs *x509.CertPool
	}
)

var (
	portMap = map[string]string{
		"http":  "80",
		"https": "443",
	}
)

func (dialer *dialer) Dial(network string, address string) (c net.Conn, err error) {
	ctx := context.Background()
	return dialer.DialContext(ctx, network, address)
}

func (dialer *dialer) DialContext(ctx context.Context, network string, address string) (c net.Conn, err error) {

	proxyNetwork := "tcp"
	proxyAddr := canonicalAddr(dialer.proxyURL)

	c, err = dialer.proxyDial(ctx, proxyNetwork, proxyAddr)
	if err != nil {
		return nil, err
	}

	if dialer.proxyURL.Scheme == "https" {
		c = tls.Client(c, &tls.Config{
			ServerName: dialer.proxyURL.Hostname(),
			RootCAs:    dialer.rootCAs,
		})
	}

	err = setupConn(ctx, c, address, dialer.proxyURL)
	if err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

func setupConn(ctx context.Context, conn net.Conn, address string, proxyURL *nurl.URL) error {

	logProxyURL := *proxyURL
	logProxyURL.User = nil

	url := "//" + address // prepend an empty scheme prefix

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, nil)
	if err != nil {
		fmt.Println(err)
		return err
	}

	req.Header.Set("Proxy-Connection", "Keep-Alive")
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := username + ":" + password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	err = req.Write(conn)
	if err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("httpproxy: failed to connect to %s with status code %d: %s", &logProxyURL, resp.StatusCode, msg)
	}

	return nil
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *nurl.URL) string {
	addr := url.Hostname()
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(addr, port)
}

func newDialer(proxyURL *nurl.URL, proxyDialer proxy.Dialer) (proxy.Dialer, error) {

	proxyDial := func(ctx context.Context, network string, address string) (c net.Conn, err error) {
		return proxyDialer.Dial(network, address)
	}
	if proxyDialer, ok := proxyDialer.(proxy.ContextDialer); ok {
		proxyDial = proxyDialer.DialContext
	}

	return &dialer{
		proxyURL:  proxyURL,
		proxyDial: proxyDial,
	}, nil
}

func init() {
	proxy.RegisterDialerType("http", newDialer)
}
