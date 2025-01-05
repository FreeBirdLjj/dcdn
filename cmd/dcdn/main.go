package main

import (
	"os"
	"os/signal"
	"syscall"

	_ "github.com/FreeBirdLjj/dcdn/pkg/http/proxy"
	tcppkg "github.com/FreeBirdLjj/dcdn/pkg/tcp"
	"github.com/FreeBirdLjj/dcdn/tcp"
)

func waitForTeardown() {

	signals := []os.Signal{
		syscall.SIGKILL,
		syscall.SIGINT,
		syscall.SIGTERM,
	}

	ch := make(chan os.Signal, 1)

	signal.Reset(signals...)
	signal.Notify(ch, signals...)

	<-ch
}

func main() {

	{
		httpSrv := tcppkg.Server{
			Addr:    ":80",
			Handler: tcp.ForwardHTTP,
		}
		defer httpSrv.Close()

		go httpSrv.ListenAndServe()
	}
	{
		httpsSrv := tcppkg.Server{
			Addr:    ":443",
			Handler: tcp.ForwardTLS,
		}
		defer httpsSrv.Close()

		go httpsSrv.ListenAndServe()
	}

	waitForTeardown()
}
