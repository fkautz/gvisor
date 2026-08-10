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
	// storeFD is the already-connected socket, donated to the gofer by the
	// runsc process that spawned it.
	storeFD int
}

var _ extension.Extension = (*Extension)(nil)

// Name implements extension.Extension.Name.
func (e *Extension) Name() string { return "casimir" }

// storeFDFlag names the gofer subcommand flag carrying the donated descriptor.
// PrepareGoferHost donates under this exact name and SetFlags reads it back;
// the two must agree or the gofer holds a descriptor it cannot find.
const storeFDFlag = "casimir-store-fd"

// SetFlags registers the descriptor flag the donation lands in.
func (e *Extension) SetFlags(f *flag.FlagSet) {
	f.IntVar(&e.storeFD, storeFDFlag, -1, "file descriptor of a connected Casimir store socket")
}

// PrepareGoferHost dials the store in the runsc process that spawns the gofer
// and donates the connected socket.
//
// IT CANNOT BE DONE IN THE GOFER. The store is named by a host path, and the
// gofer's own PrepareGofer hook runs after it has unshared its mount namespace
// and built the root it chroots into, so the path no longer resolves there --
// observed as `dial casimir store ".../bridge.sock": no such file or directory`,
// reaching the operator two layers away as an unmarshaling error on the boot
// side. Dialing here needs no dup(2): the descriptor travels as an ExtraFile,
// so the child receives it with FD_CLOEXEC clear and it survives the gofer's
// capability re-exec.
func (e *Extension) PrepareGoferHost(ctx extension.HostPrepareContext) (extension.HostPrepareResult, error) {
	socket, ok := ctx.Spec.Annotations[SocketAnnotation]
	if !ok || socket == "" {
		return extension.HostPrepareResult{}, nil
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return extension.HostPrepareResult{}, fmt.Errorf("dial casimir store %q: %w", socket, err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return extension.HostPrepareResult{}, fmt.Errorf("casimir store %q is not a unix socket", socket)
	}
	// File() returns a duplicate; the original conn is closed because only the
	// duplicate is donated.
	file, err := unixConn.File()
	unixConn.Close()
	if err != nil {
		return extension.HostPrepareResult{}, fmt.Errorf("take casimir store descriptor: %w", err)
	}
	return extension.HostPrepareResult{
		Donations: []extension.GoferDonation{{Flag: storeFDFlag, File: file}},
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
	return &connection{client: &client{conn: &fdConn{fd: e.storeFD}}}, lisafs.ConnectionOpts{
		// The served root is read-only regardless of what the spec says: these
		// bytes are verified content-addressed state, and the writable upper is
		// the runtime's own overlay.
		Readonly: true,
		// WalkStat is implemented and holds no locks on descendant Nodes.
		WalkStatSupported: true,
	}, nil
}

// SeccompRules allows the syscalls the store connection needs, which is only
// read and write.
//
// THAT SHORT LIST IS THE POINT, and it is why fdConn exists. The gofer's filter
// is installed before mount dispatch, so every syscall a backend makes while
// serving must already be allowed; a backend that reaches for the net package
// pulls in getsockopt, getsockname, and the netpoller's epoll calls, and each
// missing one kills the gofer with SIGSYS -- no panic, no log, and an EIO two
// layers away. read and write are already in the stock allowlist; naming them
// here documents the dependency rather than widening anything.
func (e *Extension) SeccompRules() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_READ:  seccomp.MatchAll{},
		unix.SYS_WRITE: seccomp.MatchAll{},
	})
}
