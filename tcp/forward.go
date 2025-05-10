package tcp

import (
	"context"
	"io"
	"net"
	"strconv"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"

	iopkg "github.com/FreeBirdLjj/dcdn/pkg/io"
)

func SniffHostAndForward(sniffer func(incomingData io.Reader) (hostname string, err error), clientConn *net.TCPConn) {

	defer clientConn.Close()

	ctx := context.Background()
	laddr := clientConn.LocalAddr().(*net.TCPAddr)
	logger := logrus.
		WithContext(ctx).
		WithFields(logrus.Fields{
			"caddr": clientConn.RemoteAddr(),
			"lport": laddr.Port,
		})

	readers := iopkg.ReplicateReader(clientConn, 2)
	defer readers[1].Close()

	srvHostName, err := func() (string, error) {
		defer readers[0].Close()
		return sniffer(readers[0])
	}()
	if err != nil {
		logger.Errorf("failed to sniff target hostname: %v", err)
		return
	}

	saddr := net.JoinHostPort(srvHostName, strconv.Itoa(laddr.Port))

	logger = logger.WithField("saddr", saddr)
	logger.Infof("connecting...")

	conn, err := proxy.Dial(ctx, "tcp", saddr)
	if err != nil {
		logger.Errorf("failed to connect: %v", err)
		return
	}
	defer conn.Close()

	logger.Infof("connected")

	errCh := make(chan error, 1)

	go func() {
		_, err := io.Copy(clientConn, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, readers[1])
		errCh <- err
	}()

	err = <-errCh
	if err != nil {
		logger.Errorf("failed to transport: %v", err)
		return
	}

	logger.Infof("finished transporting")
}
