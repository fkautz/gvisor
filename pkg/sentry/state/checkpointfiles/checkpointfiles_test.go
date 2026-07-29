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

package checkpointfiles

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const testGeneration = "00112233445566778899aabbccddeeff"

type errorReadCloser struct {
	io.Reader
	closeErr error
}

func (r errorReadCloser) Close() error {
	return r.closeErr
}

func TestReadCommittedGenerationSelectsGeneration(t *testing.T) {
	got, err := ReadCommittedGeneration(func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(testGeneration)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != testGeneration {
		t.Fatalf("generation = %q, want %q", got, testGeneration)
	}

	state, metadata, pages, err := FullCheckpointFileNames(got)
	if err != nil {
		t.Fatal(err)
	}
	for name, suffix := range map[string]string{
		state:    "/" + StateFileName,
		metadata: "/" + PagesMetadataFileName,
		pages:    "/" + PagesFileName,
	} {
		if !strings.HasPrefix(name, "generations/"+testGeneration+"/") || !strings.HasSuffix(name, suffix) {
			t.Errorf("selected object %q is not generation-scoped", name)
		}
	}
}

func TestReadCommittedGenerationLegacyOnlyOnAbsence(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func() (io.ReadCloser, error)
	}{
		{
			name: "open absent",
			open: func() (io.ReadCloser, error) { return nil, unix.ENOENT },
		},
		{
			name: "read absent",
			open: func() (io.ReadCloser, error) {
				return errorReadCloser{Reader: errorReader{unix.ENOENT}}, nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generation, err := ReadCommittedGeneration(tc.open)
			if err != nil {
				t.Fatal(err)
			}
			if generation != "" {
				t.Fatalf("generation = %q, want legacy selection", generation)
			}
			state, metadata, pages, err := FullCheckpointFileNames(generation)
			if err != nil {
				t.Fatal(err)
			}
			if state != StateFileName || metadata != PagesMetadataFileName || pages != PagesFileName {
				t.Fatalf("legacy objects = (%q, %q, %q)", state, metadata, pages)
			}
		})
	}
}

func TestReadCommittedGenerationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func() (io.ReadCloser, error)
	}{
		{
			name: "permission",
			open: func() (io.ReadCloser, error) { return nil, unix.EACCES },
		},
		{
			name: "transient read",
			open: func() (io.ReadCloser, error) {
				return errorReadCloser{Reader: errorReader{unix.EIO}}, nil
			},
		},
		{
			name: "close",
			open: func() (io.ReadCloser, error) {
				return errorReadCloser{Reader: strings.NewReader(testGeneration), closeErr: unix.EIO}, nil
			},
		},
		{
			name: "absent read with close failure",
			open: func() (io.ReadCloser, error) {
				return errorReadCloser{Reader: errorReader{unix.ENOENT}, closeErr: unix.EIO}, nil
			},
		},
		{
			name: "invalid marker",
			open: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("legacy")), nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if generation, err := ReadCommittedGeneration(tc.open); err == nil {
				t.Fatalf("selected generation %q despite non-absence marker failure", generation)
			}
		})
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestReadCommittedGenerationPreservesWrappedAbsence(t *testing.T) {
	generation, err := ReadCommittedGeneration(func() (io.ReadCloser, error) {
		return nil, errors.Join(errors.New("remote read"), unix.ENOENT)
	})
	if err != nil || generation != "" {
		t.Fatalf("ReadCommittedGeneration() = (%q, %v), want legacy", generation, err)
	}
}

type testCommitWriter struct {
	closed  bool
	aborted bool
}

func (w *testCommitWriter) Close() error {
	w.closed = true
	return nil
}

func (w *testCommitWriter) Abort() error {
	w.aborted = true
	return nil
}

func TestSaveAndCommitPublishesOnlyAfterSave(t *testing.T) {
	commit := &testCommitWriter{}
	saveCompleted := false
	if err := SaveAndCommit(func() error {
		if commit.closed {
			t.Fatal("commit marker published before save boundary returned")
		}
		saveCompleted = true
		return nil
	}, commit); err != nil {
		t.Fatal(err)
	}
	if !saveCompleted || !commit.closed || commit.aborted {
		t.Fatalf("save/commit state = completed:%t closed:%t aborted:%t", saveCompleted, commit.closed, commit.aborted)
	}
}

func TestSaveAndCommitAbortsFailedSave(t *testing.T) {
	saveErr := errors.New("injected Kernel.SaveTo failure")
	commit := &testCommitWriter{}
	if err := SaveAndCommit(func() error { return saveErr }, commit); !errors.Is(err, saveErr) {
		t.Fatalf("SaveAndCommit() error = %v, want %v", err, saveErr)
	}
	if commit.closed || !commit.aborted {
		t.Fatalf("failed save commit state = closed:%t aborted:%t", commit.closed, commit.aborted)
	}
}

func makeLocalTransaction(t *testing.T, extraNames ...string) (*os.File, []*os.File) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LocalTransactionFileName), []byte(LocalTransactionMagic), 0600); err != nil {
		t.Fatal(err)
	}
	var files []*os.File
	names := append([]string{StateFileName, PagesMetadataFileName, PagesFileName}, extraNames...)
	for _, name := range names {
		staged, err := LocalStagingFileName(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(filepath.Join(dir, staged), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("plane:" + name); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dirFile.Close()
		for _, file := range files {
			file.Close()
		}
	})
	return dirFile, files
}

func TestFinishLocalTransactionPublishesCasimirPlanes(t *testing.T) {
	dir, files := makeLocalTransaction(t, SharedBaseFileName, CasimirLayoutFileName)
	fds := make([]int, len(files))
	for i, file := range files {
		fds[i] = int(file.Fd())
	}
	if err := FinishLocalTransaction(int(dir.Fd()), fds, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		StateFileName,
		PagesMetadataFileName,
		PagesFileName,
		SharedBaseFileName,
		CasimirLayoutFileName,
	} {
		got, err := os.ReadFile(filepath.Join(dir.Name(), name))
		if err != nil {
			t.Fatal(err)
		}
		if want := "plane:" + name; string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestFinishLocalTransactionPublishesFixedPlanes(t *testing.T) {
	dir, files := makeLocalTransaction(t)
	fds := make([]int, len(files))
	for i, file := range files {
		fds[i] = int(file.Fd())
	}
	if err := FinishLocalTransaction(int(dir.Fd()), fds, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{StateFileName, PagesMetadataFileName, PagesFileName} {
		got, err := os.ReadFile(filepath.Join(dir.Name(), name))
		if err != nil {
			t.Fatal(err)
		}
		if want := "plane:" + name; string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
		staged, _ := LocalStagingFileName(name)
		if _, err := os.Lstat(filepath.Join(dir.Name(), staged)); !os.IsNotExist(err) {
			t.Errorf("staging file %q survived commit: %v", staged, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir.Name(), LocalTransactionFileName)); !os.IsNotExist(err) {
		t.Errorf("transaction marker survived commit: %v", err)
	}
}

func TestFinishLocalTransactionAbortsFailedSave(t *testing.T) {
	dir, files := makeLocalTransaction(t)
	fds := make([]int, len(files))
	for i, file := range files {
		fds[i] = int(file.Fd())
	}
	saveErr := errors.New("injected save failure")
	if err := FinishLocalTransaction(int(dir.Fd()), fds, saveErr); !errors.Is(err, saveErr) {
		t.Fatalf("FinishLocalTransaction() error = %v, want %v", err, saveErr)
	}
	entries, err := os.ReadDir(dir.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed save left local transaction entries: %v", entries)
	}
}
