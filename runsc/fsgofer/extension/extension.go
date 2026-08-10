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

// Package extension defines registration hooks for custom filesystem gofer
// extensions. The stock fsgofer handles any mount no Extension claims.
package extension

import (
	"fmt"
	"os"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/flag"
)

// Extension is implemented by alternative LisaFS backends. The first
// registered Extension whose TryHandleMount returns a non-nil implementation
// handles the mount.
type Extension interface {
	// Name identifies the extension in log messages.
	Name() string

	// TryHandleMount returns a LisaFS connection implementation and options for
	// the given mount, or (nil, lisafs.ConnectionOpts{}, nil) if this extension
	// does not handle it. A non-nil error means the extension claims the mount
	// but failed to initialize.
	//
	// mount is nil for the root filesystem (root is not present in
	// spec.Mounts). Per-sandbox config may be read from spec.Annotations.
	//
	// All returned connections run on one shared lisafs.Server so server-side
	// tree synchronization is preserved across stock and extension-backed
	// mounts.
	TryHandleMount(spec *specs.Spec, mount *specs.Mount, mountPath string, readonly bool) (lisafs.ConnectionImpl, lisafs.ConnectionOpts, error)

	// SeccompRules returns additional rules to merge into the stock
	// gofer's seccomp allowlist.
	SeccompRules() seccomp.SyscallRules
}

type setFlags interface {
	SetFlags(f *flag.FlagSet)
}

// GoferPrepareContext contains inputs available while preparing the gofer,
// before it drops capabilities and enters its final root.
type GoferPrepareContext struct {
	Spec        *specs.Spec
	ContainerID string
	BundleDir   string
}

// GoferPrepareResult contains state for gofer re-exec.
type GoferPrepareResult struct {
	// FlagOverrides are applied after setup. File descriptor values must refer
	// to descriptors with FD_CLOEXEC cleared.
	FlagOverrides map[string]string
}

type prepareGofer interface {
	PrepareGofer(ctx GoferPrepareContext) (GoferPrepareResult, error)
}

// HostPrepareContext contains inputs available in the process that spawns the
// gofer, while that process still has the caller's mount namespace, root
// directory, and host network access.
//
// PrepareGofer runs inside the gofer, after it has unshared its namespaces and
// set up the root it will chroot into. An extension backed by a host resource
// that is named by a path -- a service socket, for instance -- cannot open it
// there, because the name no longer resolves. Such an extension must open it
// here instead and donate the descriptor.
type HostPrepareContext struct {
	Spec        *specs.Spec
	ContainerID string
	BundleDir   string
}

// GoferDonation is one file passed from the spawning process to the gofer.
type GoferDonation struct {
	// Flag is the gofer subcommand flag that receives the descriptor number in
	// the child. The extension must register it in SetFlags.
	Flag string

	// File is donated to the gofer. The spawning process takes ownership and
	// closes it once the gofer has started; the descriptor the child receives
	// has FD_CLOEXEC clear, so it also survives the gofer's capability re-exec.
	File *os.File
}

// HostPrepareResult contains state the spawning process passes to the gofer.
type HostPrepareResult struct {
	// Donations are applied in order, so the flags they produce are
	// deterministic across runs.
	Donations []GoferDonation
}

type prepareGoferHost interface {
	PrepareGoferHost(ctx HostPrepareContext) (HostPrepareResult, error)
}

var registered []Extension

// Register adds e to the extension list. Must be called during init or
// early in main, before Registered is iterated.
func Register(e Extension) {
	registered = append(registered, e)
}

// Registered returns all registered extensions in registration order.
func Registered() []Extension {
	return registered
}

// SetFlags lets registered extensions add gofer flags.
func SetFlags(f *flag.FlagSet) {
	for _, e := range registered {
		if setter, ok := e.(setFlags); ok {
			setter.SetFlags(f)
		}
	}
}

// PrepareGofer lets registered extensions prepare state and merges flag
// overrides for gofer re-exec.
func PrepareGofer(ctx GoferPrepareContext) (GoferPrepareResult, error) {
	var result GoferPrepareResult
	for _, e := range registered {
		prepare, ok := e.(prepareGofer)
		if !ok {
			continue
		}
		extensionResult, err := prepare.PrepareGofer(ctx)
		if err != nil {
			return GoferPrepareResult{}, err
		}
		for key, value := range extensionResult.FlagOverrides {
			if result.FlagOverrides == nil {
				result.FlagOverrides = make(map[string]string)
			}
			result.FlagOverrides[key] = value
		}
	}
	return result, nil
}

// PrepareGoferHost lets registered extensions open host resources in the
// spawning process and collects the files they donate to the gofer.
//
// Two extensions claiming the same flag is a configuration error, not a
// last-one-wins merge: the loser's file would be donated with no flag naming
// it, so the gofer would hold a descriptor it cannot find and the extension
// would fail later with nothing pointing back here. On error the caller must
// close every file returned so far; ownership does not transfer until the
// caller donates them.
func PrepareGoferHost(ctx HostPrepareContext) (HostPrepareResult, error) {
	var result HostPrepareResult
	claimed := make(map[string]string)
	for _, e := range registered {
		prepare, ok := e.(prepareGoferHost)
		if !ok {
			continue
		}
		extensionResult, err := prepare.PrepareGoferHost(ctx)
		if err != nil {
			closeDonations(result.Donations)
			closeDonations(extensionResult.Donations)
			return HostPrepareResult{}, fmt.Errorf("extension %q: %w", e.Name(), err)
		}
		for _, donation := range extensionResult.Donations {
			if owner, ok := claimed[donation.Flag]; ok {
				closeDonations(result.Donations)
				closeDonations(extensionResult.Donations)
				return HostPrepareResult{}, fmt.Errorf("extensions %q and %q both donate to flag %q", owner, e.Name(), donation.Flag)
			}
			claimed[donation.Flag] = e.Name()
		}
		result.Donations = append(result.Donations, extensionResult.Donations...)
	}
	return result, nil
}

func closeDonations(donations []GoferDonation) {
	for _, donation := range donations {
		if donation.File != nil {
			_ = donation.File.Close()
		}
	}
}
