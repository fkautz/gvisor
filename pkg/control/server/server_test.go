// Copyright 2026 The gVisor Authors.
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

package server

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

type scriptedServerSocket struct {
	results []scriptedAccept
	calls   int
}

type scriptedAccept struct {
	conn *unet.Socket
	err  error
}

func (*scriptedServerSocket) FD() int       { return -1 }
func (*scriptedServerSocket) Listen() error { return nil }
func (*scriptedServerSocket) Close() error  { return nil }

func (s *scriptedServerSocket) Accept() (*unet.Socket, error) {
	if s.calls >= len(s.results) {
		panic("unexpected Accept call")
	}
	result := s.results[s.calls]
	s.calls++
	return result.conn, result.err
}

func TestServeRetriesTransientErrorThenAcceptsConnection(t *testing.T) {
	terminal := errors.New("terminal accept failure")
	accepted, peer, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("SocketPair() error = %v", err)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("peer.Close() error = %v", err)
	}
	socket := &scriptedServerSocket{
		results: []scriptedAccept{
			{err: fmt.Errorf("interrupted: %w", unix.EINTR)},
			{err: fmt.Errorf("aborted: %w", unix.ECONNABORTED)},
			{conn: accepted},
			{err: terminal},
		},
	}
	s := New(nil)
	s.socket = socket
	defer s.server.Load().Stop(0)

	err = s.serve()
	if !errors.Is(err, terminal) {
		t.Fatalf("serve() error = %v, want terminal cause %v", err, terminal)
	}
	if !errors.Is(s.ServeError(), terminal) {
		t.Fatalf("ServeError() = %v, want terminal cause %v", s.ServeError(), terminal)
	}
	if socket.calls != 4 {
		t.Fatalf("Accept calls = %d, want 4", socket.calls)
	}
	if retryableAcceptError(unix.EPROTO) {
		t.Fatal("retryableAcceptError(EPROTO) = true, want false")
	}
}

func TestStartServingReportsFatalAcceptExit(t *testing.T) {
	socket := &scriptedServerSocket{results: []scriptedAccept{{err: unix.EINVAL}}}
	s := New(nil)
	s.socket = socket
	fatal := make(chan error, 1)
	s.fatalExit = func(err error) {
		fatal <- err
	}

	if err := s.StartServing(); err != nil {
		t.Fatalf("StartServing() error = %v", err)
	}
	s.Wait()
	select {
	case err := <-fatal:
		if !errors.Is(err, unix.EINVAL) {
			t.Fatalf("fatal exit error = %v, want EINVAL", err)
		}
	default:
		t.Fatal("fatal exit was not propagated")
	}
	if !errors.Is(s.ServeError(), unix.EINVAL) {
		t.Fatalf("ServeError() = %v, want EINVAL", s.ServeError())
	}
}

func TestServeTreatsIntentionalCloseAsCleanExit(t *testing.T) {
	socket := &scriptedServerSocket{results: []scriptedAccept{{err: unix.EBADF}}}
	s := New(nil)
	s.socket = socket
	s.stopping.Store(true)

	if err := s.serve(); err != nil {
		t.Fatalf("serve() error = %v, want nil", err)
	}
	if err := s.ServeError(); err != nil {
		t.Fatalf("ServeError() = %v, want nil", err)
	}
}

type testState struct{}

type testStateArgs struct {
	Sequence int
}

type testStateResult struct {
	Sequence int
}

func (testState) Read(args *testStateArgs, result *testStateResult) error {
	result.Sequence = args.Sequence
	return nil
}

func TestRepeatedStateConnectivityKeepsAcceptLoopLive(t *testing.T) {
	addr := fmt.Sprintf("\x00runsc-control-server-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	s, err := Create(addr)
	if err != nil {
		t.Fatalf("Create(%q) error = %v", addr, err)
	}
	s.Register(testState{})
	if err := s.StartServing(); err != nil {
		t.Fatalf("StartServing() error = %v", err)
	}

	for i := 0; i < 32; i++ {
		conn, err := unet.Connect(addr, false)
		if err != nil {
			t.Fatalf("Connect(%d) error = %v", i, err)
		}
		client := urpc.NewClient(conn)
		var result testStateResult
		if err := client.Call("testState.Read", &testStateArgs{Sequence: i}, &result); err != nil {
			t.Fatalf("state Call(%d) error = %v", i, err)
		}
		if result.Sequence != i {
			t.Fatalf("state Call(%d) result = %d", i, result.Sequence)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("client.Close(%d) error = %v", i, err)
		}
	}
	s.Stop(0)
	if err := s.ServeError(); err != nil {
		t.Fatalf("ServeError() after repeated connectivity = %v, want nil", err)
	}
}
