package httpproxy

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	nurl "net/url"
	"testing"
	_ "unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

//go:linkname parseBasicAuth net/http.parseBasicAuth
func parseBasicAuth(auth string) (username, password string, ok bool)

func Test_dialer_DialContext(t *testing.T) {

	t.Parallel()

	t.Run("successful cases", func(t *testing.T) {

		t.Parallel()

		testF := func(t *testing.T, https bool, auth *nurl.Userinfo) {

			t.Parallel()

			targetAddr := "target.addr:1234"

			ctx := context.Background()

			proxySrv := httptest.NewUnstartedServer(http.HandlerFunc(func(respWriter http.ResponseWriter, req *http.Request) {

				assert.Equal(t, http.MethodConnect, req.Method)
				assert.Equal(t, targetAddr, req.URL.Host)
				assert.Equal(t, "Keep-Alive", req.Header.Get("Proxy-Connection"))

				if auth != nil {
					reqUser, reqPasswd, ok := parseBasicAuth(req.Header.Get("Proxy-Authorization"))
					assert.True(t, ok)
					assert.Equal(t, auth.Username(), reqUser)
					passwd, _ := auth.Password()
					assert.Equal(t, passwd, reqPasswd)
				}

				respWriter.WriteHeader(http.StatusOK)
			}))
			if https {
				proxySrv.StartTLS()
			} else {
				proxySrv.Start()
			}
			defer proxySrv.Close()

			proxyURL, err := nurl.Parse(proxySrv.URL)
			require.NoError(t, err)

			proxyURL.User = auth

			dialer := dialer{
				proxyURL:  proxyURL,
				proxyDial: proxy.Direct.DialContext,
			}
			if https {
				dialer.rootCAs = getRootCAsFromTestTLSServer(proxySrv)
			}

			conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
			require.NoError(t, err)

			defer conn.Close()

			assert.NotNil(t, conn)
		}

		for _, https := range []bool{false, true} {
			for _, auth := range []*nurl.Userinfo{nil, nurl.UserPassword("user", "passwd")} {
				t.Run(fmt.Sprintf("https: %v, auth: %s", https, auth), func(t *testing.T) {
					testF(t, https, auth)
				})
			}
		}
	})
}

func getRootCAsFromTestTLSServer(testTLSSrv *httptest.Server) *x509.CertPool {
	return testTLSSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}
