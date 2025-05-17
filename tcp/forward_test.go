package tcp

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSniffHostAndForward(t *testing.T) {

	t.Parallel()

	t.Run("should forward traffic to the sniffed host with the same port", func(t *testing.T) {

		t.Parallel()

		clientSendMsg := []byte("client-send-msg")
		clientRecvMsg := []byte("client-recv-msg")

		sniffer := func(r io.Reader) (hostname string, err error) {

			sniffingBuf, err := io.ReadAll(r)
			require.NoError(t, err)

			assert.Equal(t, clientSendMsg, sniffingBuf)

			return "localhost", nil
		}

		srv, err := net.ListenTCP("tcp", &net.TCPAddr{
			IP: []byte{127, 0, 0, 1},
		})
		require.NoError(t, err)

		defer srv.Close()

		clientRead := make(chan []byte, 1)
		proxyRead := make(chan []byte, 1)
		nextConn := make(chan struct{}, 1)

		// the initial client connection
		go sendMsgAndWaitForResp(
			t,
			func() (*net.TCPConn, error) {
				return net.DialTCP("tcp", nil, srv.Addr().(*net.TCPAddr))
			},
			clientSendMsg,
			clientRead,
		)

		// the 2nd server connection: mock the target server
		go sendMsgAndWaitForResp(
			t,
			func() (*net.TCPConn, error) {
				<-nextConn
				return srv.AcceptTCP()
			},
			clientRecvMsg,
			proxyRead,
		)

		// the 1st server connection: run the handler
		srvConn, err := srv.AcceptTCP()
		require.NoError(t, err)

		defer srvConn.Close()

		nextConn <- struct{}{}

		SniffHostAndForward(sniffer, srvConn)

		assert.Equal(t, clientSendMsg, <-proxyRead)
		assert.Equal(t, clientRecvMsg, <-clientRead)
	})
}

func sendMsgAndWaitForResp(t *testing.T, connFn func() (*net.TCPConn, error), msg []byte, ch chan<- []byte) {

	conn, err := connFn()
	require.NoError(t, err)

	defer conn.Close()

	_, err = conn.Write(msg)
	require.NoError(t, err)

	err = conn.CloseWrite()
	require.NoError(t, err)

	resp, err := io.ReadAll(conn)
	require.NoError(t, err)

	ch <- resp
}
