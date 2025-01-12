package tcp

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type (
	tlsClientTestConn struct {
		net.Conn

		writeBuf bytes.Buffer
	}
)

func (conn *tlsClientTestConn) Write(b []byte) (n int, err error) {
	return conn.writeBuf.Write(b)
}

func (conn *tlsClientTestConn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func Test_sniffTLSServerName(t *testing.T) {

	t.Parallel()

	t.Run("should successfully sniff the TLS server name", func(t *testing.T) {

		t.Parallel()

		serverName := "server.name"

		underlyingConn := tlsClientTestConn{}
		tlsClientConfig := tls.Config{
			ServerName: serverName,
		}

		// Perform a handshake but ignore the returned error since we don't
		// respond to this handshake message.
		tls.Client(&underlyingConn, &tlsClientConfig).Handshake()

		host, err := sniffTLSServerName(&underlyingConn.writeBuf)
		require.NoError(t, err)

		assert.Equal(t, serverName, host)
	})
}
