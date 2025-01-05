package tcp

import (
	"fmt"
	"net"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

type (
	Server struct {
		Addr    string
		Handler func(conn *net.TCPConn)

		inShutdown atomic.Bool
		listener   *net.TCPListener
	}
)

func (srv *Server) Close() error {
	srv.inShutdown.Store(true)
	return srv.listener.Close()
}

func (srv *Server) shuttingDown() bool {
	return srv.inShutdown.Load()
}

func (srv *Server) ListenAndServe() error {

	laddr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}

	srv.listener = listener

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if srv.shuttingDown() {
				return fmt.Errorf("tcp: Server for %s closed", srv.Addr)
			}
			logrus.Errorf("failed to accept new connection: %v", err)
			continue
		}
		go srv.Handler(conn)
	}
}
