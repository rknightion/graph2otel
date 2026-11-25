package callnotify

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/netutil"
)

// Serve runs the dedicated TLS endpoint on an already-bound listener. No
// admin routes, default mux, request logging or plaintext forwarding are used.
func Serve(ctx context.Context, listener net.Listener, certificate tls.Certificate, handler *Receiver) error {
	listener = tls.NewListener(netutil.LimitListener(listener, 64), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          log.New(io.Discard, "", 0), // TLS errors may include caller data
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = server.Close()
	})
	err := server.Serve(listener)
	if stop() {
		_ = server.Close() // the listener may have stopped before ctx was cancelled
	} else {
		<-done
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
