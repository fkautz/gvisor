// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package server provides a basic control server interface.

Note that no objects are registered by default. Users must provide their own
implementations of the control interface.
*/
package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

// curUID is the unix user ID of the user that the control server is running as.
var curUID = os.Getuid()

type serverSocket interface {
	FD() int
	Listen() error
	Accept() (*unet.Socket, error)
	Close() error
}

type serveError struct {
	err error
}

// Server is a basic control server.
type Server struct {
	// socket is our bound socket.
	socket serverSocket

	// server is our rpc server.
	server atomic.Pointer[urpc.Server]

	// stopping is set before Stop closes the listening socket.
	stopping atomic.Bool

	// serveErr records an unexpected accept-loop exit before the serving
	// goroutine fails closed.
	serveErr atomic.Pointer[serveError]

	// fatalExit terminates the sandbox after an unexpected accept-loop exit.
	// Tests replace this callback to observe the fail-closed boundary.
	fatalExit func(error)

	// wg waits for the accept loop to terminate.
	wg sync.WaitGroup
}

// New returns a new bound control server.
func New(socket *unet.ServerSocket) *Server {
	s := &Server{
		socket:    socket,
		fatalExit: func(err error) { panic(err) },
	}
	s.server.Store(urpc.NewServer())
	return s
}

// ResetServer resets the server, clearing all registered objects. It stops the
// old server asynchronously.
func (s *Server) ResetServer() {
	if old := s.server.Swap(urpc.NewServer()); old != nil {
		go old.Stop(0)
	}
}

// FD returns the file descriptor that the server is running on.
func (s *Server) FD() int {
	return s.socket.FD()
}

// Wait waits for the main server goroutine to exit. This should be
// called after a call to Serve.
func (s *Server) Wait() {
	s.wg.Wait()
}

// ServeError returns the exact unexpected error that terminated the accept
// loop, if any. Callers that require a stable result must call Wait first.
func (s *Server) ServeError() error {
	if err := s.serveErr.Load(); err != nil {
		return err.err
	}
	return nil
}

// Stop stops the server. Note that this function should only be called once
// and the server should not be used afterwards.
func (s *Server) Stop(timeout time.Duration) {
	s.stopping.Store(true)
	s.socket.Close()
	s.Wait()

	// This will cause existing clients to be terminated safely. If the
	// registered handlers have a Stop callback, it will be called.
	s.server.Load().Stop(timeout)
}

// StartServing starts listening for connect and spawns the main service
// goroutine for handling incoming control requests. StartServing does not
// block; to wait for the control server to exit, call Wait.
func (s *Server) StartServing() error {
	// Actually start listening.
	if err := s.socket.Listen(); err != nil {
		return err
	}

	ready := make(chan struct{})
	s.wg.Add(1)
	go func() { // S/R-SAFE: does not impact state directly.
		defer s.wg.Done()
		close(ready)
		if err := s.serve(); err != nil {
			s.fatalExit(err)
		}
	}()
	<-ready

	return nil
}

// serve is the body of the main service goroutine. It handles incoming control
// connections and dispatches requests to registered objects.
func (s *Server) serve() error {
	for {
		// Accept clients.
		conn, err := s.socket.Accept()
		if err != nil {
			if s.stopping.Load() && errors.Is(err, unix.EBADF) {
				return nil
			}
			if retryableAcceptError(err) {
				continue
			}
			err = fmt.Errorf("control server accept loop terminated: %w", err)
			s.serveErr.Store(&serveError{err: err})
			return err
		}

		// Handle the connection non-blockingly.
		s.server.Load().StartHandling(conn)
	}
}

// retryableAcceptError is deliberately limited to interruption and an
// aborted pending connection. Other errors terminate the sandbox rather than
// silently removing its control plane.
func retryableAcceptError(err error) bool {
	return errors.Is(err, unix.EINTR) || errors.Is(err, unix.ECONNABORTED)
}

// Register registers a specific control interface with the server.
func (s *Server) Register(obj any) {
	s.server.Load().Register(obj)
}

// CreateFromFD creates a new control bound to the given 'fd'. It has no
// registered interfaces and will not start serving until StartServing is
// called.
func CreateFromFD(fd int) (*Server, error) {
	socket, err := unet.NewServerSocket(fd)
	if err != nil {
		return nil, err
	}
	return New(socket), nil
}

// Create creates a new control server with an abstract unix socket
// with the given address, which must must be unique and a valid
// abstract socket name.
func Create(addr string) (*Server, error) {
	socket, err := CreateSocket(addr)
	if err != nil {
		return nil, err
	}
	return CreateFromFD(socket)
}

// CreateSocket creates a socket that can be used with control server,
// but doesn't start control server.  'addr' must be a valid and unique
// abstract socket name.  Returns socket's FD, -1 in case of error.
func CreateSocket(addr string) (int, error) {
	if addr[0] != 0 && len(addr) >= linux.UnixPathMax {
		// This is not an abstract socket path. It is a filesystem path.
		// UDS bind fails when the len(socket path) >= UNIX_PATH_MAX. Instead
		// try opening the parent and attempt to shorten the path via procfs.
		dirFD, err := unix.Open(filepath.Dir(addr), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return -1, fmt.Errorf("failed to open parent directory of %q", addr)
		}
		defer unix.Close(dirFD)
		name := filepath.Base(addr)
		addr = fmt.Sprintf("/proc/self/fd/%d/%s", dirFD, name)
		if len(addr) >= linux.UnixPathMax {
			// Urgh... This is just doomed to fail. Ask caller to use a shorter name.
			return -1, fmt.Errorf("socket name %q is too long, use a shorter name", name)
		}
	}
	socket, err := unet.Bind(addr, false)
	if err != nil {
		return -1, err
	}
	return socket.Release()
}
