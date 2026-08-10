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

package casimir

import (
	"fmt"
	"net"
	"os"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/fsgofer/extension"
)

// SocketAnnotation names Casimir's bridge socket in the OCI spec. Its presence
// is what makes this extension claim the root; absence leaves every mount to
// the stock fsgofer.
//
// THE LITERAL MUST MATCH bridgeSocketAnnotation IN CASIMIR's ADAPTER. The two
// sides are compile-time independent -- nothing links them -- so a mismatch
// produces no build error and no runtime error: the extension simply never
// claims the root and the stock fsgofer serves it from host files instead. That
// is a silent fallback to the eager behaviour this backend exists to remove,
// and only an end-to-end test can catch it.
const SocketAnnotation = "dev.casimir.bridge-socket"

func init() {
	extension.Register(&Extension{})
}

// Extension serves a container root from Casimir's store.
type Extension struct {
	// storeFD is the already-connected socket, passed across the gofer's
	// capability re-exec by PrepareGofer.
	storeFD int
}

var _ extension.Extension = (*Extension)(nil)

// Name implements extension.Extension.Name.
func (e *Extension) Name() string { return "casimir" }

// SetFlags registers the descriptor flag PrepareGofer overrides.
func (e *Extension) SetFlags(f *flag.FlagSet) {
	f.IntVar(&e.storeFD, "casimir-store-fd", -1, "file descriptor of a connected Casimir store socket")
}

// PrepareGofer dials the store BEFORE the gofer drops capabilities and enters
// its final root, then hands the descriptor across the re-exec.
//
// THE dup(2) IS NOT OPTIONAL. Go sets FD_CLOEXEC on everything it opens, so the
// dialed connection would not survive the re-exec; dup(2) returns a descriptor
// with the flag clear, which is exactly what FlagOverrides documents it needs.
// Getting this wrong produces no error here and an EIO from the Sentry later,
// naming nothing.
func (e *Extension) PrepareGofer(ctx extension.GoferPrepareContext) (extension.GoferPrepareResult, error) {
	socket, ok := ctx.Spec.Annotations[SocketAnnotation]
	if !ok || socket == "" {
		return extension.GoferPrepareResult{}, nil
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return extension.GoferPrepareResult{}, fmt.Errorf("dial casimir store %q: %w", socket, err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return extension.GoferPrepareResult{}, fmt.Errorf("casimir store %q is not a unix socket", socket)
	}
	file, err := unixConn.File()
	if err != nil {
		conn.Close()
		return extension.GoferPrepareResult{}, fmt.Errorf("take casimir store descriptor: %w", err)
	}
	// The *os.File and the original conn are both closed: only the duplicate,
	// with FD_CLOEXEC cleared, is meant to survive.
	duplicated, err := unix.Dup(int(file.Fd()))
	file.Close()
	unixConn.Close()
	if err != nil {
		return extension.GoferPrepareResult{}, fmt.Errorf("dup casimir store descriptor: %w", err)
	}
	return extension.GoferPrepareResult{
		FlagOverrides: map[string]string{"casimir-store-fd": fmt.Sprintf("%d", duplicated)},
	}, nil
}

// TryHandleMount claims the container root when a store socket was configured.
//
// mount is nil for the root, which is the only thing this extension serves: a
// named mount is someone else's filesystem and the stock fsgofer handles it.
func (e *Extension) TryHandleMount(spec *specs.Spec, mount *specs.Mount, mountPath string, readonly bool) (lisafs.ConnectionImpl, lisafs.ConnectionOpts, error) {
	if _, ok := spec.Annotations[SocketAnnotation]; !ok {
		return nil, lisafs.ConnectionOpts{}, nil
	}
	if mount != nil {
		return nil, lisafs.ConnectionOpts{}, nil
	}
	if e.storeFD < 0 {
		return nil, lisafs.ConnectionOpts{}, fmt.Errorf(
			"casimir store socket %q was configured but no descriptor survived the gofer re-exec",
			spec.Annotations[SocketAnnotation])
	}
	conn, err := net.FileConn(os.NewFile(uintptr(e.storeFD), "casimir-store"))
	if err != nil {
		return nil, lisafs.ConnectionOpts{}, fmt.Errorf("adopt casimir store descriptor: %w", err)
	}
	return &connection{client: &client{conn: conn}}, lisafs.ConnectionOpts{
		// The served root is read-only regardless of what the spec says: these
		// bytes are verified content-addressed state, and the writable upper is
		// the runtime's own overlay.
		Readonly: true,
		// WalkStat is implemented and holds no locks on descendant Nodes.
		WalkStatSupported: true,
	}, nil
}

// SeccompRules allows the syscalls the store connection needs.
//
// IT IS NOT OPTIONAL FOR A SOCKET-BACKED BACKEND. net.FileConn issues fcntl to
// set O_NONBLOCK, and the gofer's filter installs before mount dispatch. Without
// fcntl the gofer dies on SIGSYS with no panic and no log -- just an EIO from
// the Sentry. That failure was diagnosed from a kernel audit record
// (type=1326 sig=31 syscall=72), not guessed.
func (e *Extension) SeccompRules() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_FCNTL:    seccomp.MatchAll{},
		unix.SYS_READ:     seccomp.MatchAll{},
		unix.SYS_WRITE:    seccomp.MatchAll{},
		unix.SYS_PPOLL:    seccomp.MatchAll{},
		unix.SYS_RECVFROM: seccomp.MatchAll{},
		unix.SYS_SENDTO:   seccomp.MatchAll{},
	})
}
