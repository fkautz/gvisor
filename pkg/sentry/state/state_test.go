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

package state

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

func newTestCheckpointCommit(t *testing.T, dst *bytes.Buffer, generation string) *stateio.BufWriter {
	t.Helper()
	commit, err := stateio.NewBufWriter(stateio.NewIOWriter(dst, 4096, 1, 1), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commit.Write([]byte(generation)); err != nil {
		t.Fatal(err)
	}
	return commit
}

func TestSaveKernelToCheckpointPublishesCommitAfterPlanes(t *testing.T) {
	const generation = "00112233445566778899aabbccddeeff"
	var commitObject bytes.Buffer
	commit := newTestCheckpointCommit(t, &commitObject, generation)
	var planesFinalized bool
	if err := saveKernelToCheckpoint(func() error {
		if commitObject.Len() != 0 {
			t.Fatal("commit marker published before Kernel.SaveTo returned")
		}
		planesFinalized = true
		return nil
	}, &commit); err != nil {
		t.Fatal(err)
	}
	if !planesFinalized {
		t.Fatal("Kernel.SaveTo boundary was not driven")
	}
	if commit != nil {
		t.Fatal("published commit remained owned by SaveOpts")
	}
	if got := commitObject.String(); got != generation {
		t.Fatalf("commit marker = %q, want %q", got, generation)
	}
}

func TestSaveKernelToCheckpointAbortsCommitOnPlaneFailure(t *testing.T) {
	const generation = "00112233445566778899aabbccddeeff"
	var commitObject bytes.Buffer
	commit := newTestCheckpointCommit(t, &commitObject, generation)
	saveErr := errors.New("injected Kernel.SaveTo failure")
	if err := saveKernelToCheckpoint(func() error {
		return saveErr
	}, &commit); !errors.Is(err, saveErr) {
		t.Fatalf("saveKernelToCheckpoint() error = %v, want %v", err, saveErr)
	}
	if commit != nil {
		t.Fatal("aborted commit remained owned by SaveOpts")
	}
	if commitObject.Len() != 0 {
		t.Fatalf("failed planes published commit marker %q", commitObject.String())
	}
}

type testSaveKernel struct {
	called bool
	err    error
}

func (*testSaveKernel) Pause()             {}
func (*testSaveKernel) ReceiveTaskStates() {}
func (*testSaveKernel) Unpause()           {}
func (*testSaveKernel) SaveCasimirLayout(context.Context, io.Writer) error {
	return nil
}
func (*testSaveKernel) SetSaveSuccess(bool)          {}
func (*testSaveKernel) SetSaveError(error)           {}
func (*testSaveKernel) BeforeResume(context.Context) {}
func (*testSaveKernel) Kill(linux.WaitStatus)        {}

func (k *testSaveKernel) SaveTo(_ context.Context, state, metadata io.WriteCloser, pages stateio.AsyncWriter, _ *os.File, _, _ bool) error {
	k.called = true
	if k.err != nil {
		state.Close()
		metadata.Close()
		pages.Close()
		return k.err
	}
	if _, err := state.Write([]byte("runtime")); err != nil {
		return err
	}
	if _, err := metadata.Write([]byte("metadata")); err != nil {
		return err
	}
	return errors.Join(state.Close(), metadata.Close(), pages.Finalize(), pages.Close())
}

type testSaveWatchdog struct{}

func (*testSaveWatchdog) Stop()  {}
func (*testSaveWatchdog) Start() {}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func TestSaveDrivesKernelSaveToAndCommitResolution(t *testing.T) {
	for _, tc := range []struct {
		name       string
		saveErr    error
		wantCommit bool
	}{
		{name: "commit", wantCommit: true},
		{name: "abort", saveErr: errors.New("injected Kernel.SaveTo failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var destination, metadata, pages, commitObject bytes.Buffer
			commit := newTestCheckpointCommit(t, &commitObject, "00112233445566778899aabbccddeeff")
			opts := SaveOpts{
				Destination:      &destination,
				PagesMetadata:    nopWriteCloser{&metadata},
				PagesFile:        stateio.NewIOWriter(&pages, 4096, 1, 1),
				CheckpointCommit: commit,
				Resume:           true,
			}
			defer opts.Close()
			k := &testSaveKernel{err: tc.saveErr}
			err := opts.Save(context.Background(), k, &testSaveWatchdog{})
			if tc.saveErr == nil && err != nil {
				t.Fatal(err)
			}
			if tc.saveErr != nil && !errors.Is(err, tc.saveErr) {
				t.Fatalf("Save() error = %v, want %v", err, tc.saveErr)
			}
			if !k.called {
				t.Fatal("Save() did not call Kernel.SaveTo")
			}
			if got := commitObject.Len() != 0; got != tc.wantCommit {
				t.Fatalf("commit published = %t, want %t", got, tc.wantCommit)
			}
			if opts.CheckpointCommit != nil {
				t.Fatal("Save() retained resolved commit marker")
			}
		})
	}
}
