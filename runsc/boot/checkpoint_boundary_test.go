// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package boot

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/state/stateipc"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

func testSaveFDs(t *testing.T, count int) []*fd.FD {
	t.Helper()
	var fds []*fd.FD
	for range count {
		file, err := os.CreateTemp(t.TempDir(), "save-plane")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		dup, err := fd.NewFromFile(file)
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, dup)
	}
	t.Cleanup(func() {
		for _, file := range fds {
			file.Close()
		}
	})
	return fds
}

func TestWorkloadSaveOptsAlwaysSplitPlanesAndGenerateGoferCommit(t *testing.T) {
	for _, compression := range []statefile.CompressionLevel{
		statefile.CompressionLevelNone,
		statefile.CompressionLevelFlateBestSpeed,
	} {
		t.Run(string(compression), func(t *testing.T) {
			spec := &specs.Spec{Annotations: map[string]string{
				annotationCheckpointCompression: string(compression),
			}}
			local, err := saveOptsFromSpec(spec, testSaveFDs(t, 3), false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, file := range local.Files {
					file.Close()
				}
			}()
			if !local.HavePagesFile || local.CheckpointGeneration != "" {
				t.Fatalf("local opts: HavePagesFile=%t generation=%q", local.HavePagesFile, local.CheckpointGeneration)
			}

			gofer, err := saveOptsFromSpec(spec, testSaveFDs(t, 1), true)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, file := range gofer.Files {
					file.Close()
				}
			}()
			if !gofer.HavePagesFile || !checkpointfiles.ValidGeneration(gofer.CheckpointGeneration) {
				t.Fatalf("gofer opts: HavePagesFile=%t generation=%q", gofer.HavePagesFile, gofer.CheckpointGeneration)
			}
		})
	}
}

func TestWorkloadSaveOptsRequiresCasimirLayoutWithSharedBase(t *testing.T) {
	spec := &specs.Spec{Annotations: map[string]string{}}
	local, err := saveOptsFromSpec(spec, testSaveFDs(t, 5), false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, file := range local.Files {
			file.Close()
		}
	}()
	if !local.HavePagesFile || !local.SharedBase || len(local.Files) != 5 {
		t.Fatalf("shared-base opts: HavePagesFile=%t SharedBase=%t files=%d, want true/true/5", local.HavePagesFile, local.SharedBase, len(local.Files))
	}
	if _, err := saveOptsFromSpec(spec, testSaveFDs(t, 4), false); err == nil {
		t.Fatal("shared base without authoritative Casimir layout was accepted")
	}
}

func TestFinishConfiguredSaveResolvesWorkloadTransaction(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sharedBase bool
		saveErr    error
	}{
		{name: "commit"},
		{name: "abort", saveErr: fs.ErrInvalid},
		{name: "commit shared base", sharedBase: true},
		{name: "abort shared base", sharedBase: true, saveErr: fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, checkpointfiles.LocalTransactionFileName), []byte(checkpointfiles.LocalTransactionMagic), 0600); err != nil {
				t.Fatal(err)
			}
			var files []*os.File
			names := []string{
				checkpointfiles.StateFileName,
				checkpointfiles.PagesMetadataFileName,
				checkpointfiles.PagesFileName,
			}
			if tc.sharedBase {
				names = append(names, checkpointfiles.SharedBaseFileName, checkpointfiles.CasimirLayoutFileName)
			}
			for _, name := range names {
				staged, err := checkpointfiles.LocalStagingFileName(name)
				if err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(filepath.Join(dir, staged), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString(name); err != nil {
					t.Fatal(err)
				}
				files = append(files, file)
			}
			fds, err := fd.NewFromFiles(files)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				file.Close()
			}
			dirFile, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			dirFD, err := fd.NewFromFile(dirFile)
			dirFile.Close()
			if err != nil {
				t.Fatal(err)
			}
			err = finishConfiguredSave(fds, dirFD, tc.saveErr)
			if tc.saveErr == nil && err != nil {
				t.Fatal(err)
			}
			if tc.saveErr != nil && !errors.Is(err, tc.saveErr) {
				t.Fatalf("finishConfiguredSave() error = %v, want %v", err, tc.saveErr)
			}
			for _, name := range names {
				got, err := os.ReadFile(filepath.Join(dir, name))
				if tc.saveErr == nil {
					if err != nil || string(got) != name {
						t.Errorf("published %q = %q, %v", name, got, err)
					}
				} else if !os.IsNotExist(err) {
					t.Errorf("aborted plane %q remains: %v", name, err)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, checkpointfiles.LocalTransactionFileName)); !os.IsNotExist(err) {
				t.Errorf("resolved transaction marker remains: %v", err)
			}
		})
	}
}

type checkpointReadServer struct {
	mu        sync.Mutex
	objects   map[string][]byte
	markerErr error
	opened    []string
}

func (*checkpointReadServer) Destroy() {}

func (s *checkpointReadServer) OpenRead(path string) (stateio.AsyncReader, error) {
	s.mu.Lock()
	s.opened = append(s.opened, path)
	s.mu.Unlock()
	if path == checkpointfiles.CommitFileName && s.markerErr != nil {
		return stateio.NewIOReader(testErrorReader{s.markerErr}, 4096, 1, 1), nil
	}
	data, ok := s.objects[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return stateio.NewIOReader(bytes.NewReader(data), 4096, 1, 1), nil
}

func (*checkpointReadServer) OpenWrite(string) (stateio.AsyncWriter, error) {
	panic("unexpected write")
}

type testErrorReader struct {
	err error
}

func (r testErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func checkpointGoferRestoreOpts(t *testing.T, serverImpl *checkpointReadServer) (RestoreOpts, func()) {
	t.Helper()
	usrv := urpc.NewServer()
	server, err := stateipc.NewAsyncFileServer(serverImpl)
	if err != nil {
		t.Fatal(err)
	}
	usrv.Register(server)
	clientSock, serverSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatal(err)
	}
	usrv.StartHandling(serverSock)
	clientFD, err := clientSock.Release()
	if err != nil {
		t.Fatal(err)
	}
	clientFile := os.NewFile(uintptr(clientFD), "checkpoint-gofer-restore-test")
	return RestoreOpts{
			UseCheckpointGofer: true,
			FilePayload:        urpc.FilePayload{Files: []*os.File{clientFile}},
		}, func() {
			clientFile.Close()
			usrv.Stop(time.Second)
		}
}

func TestGetRestoreReadersForCheckpointGoferSelectsCommittedGeneration(t *testing.T) {
	const generation = "00112233445566778899aabbccddeeff"
	stateName, metadataName, pagesName, err := checkpointfiles.FullCheckpointFileNames(generation)
	if err != nil {
		t.Fatal(err)
	}
	server := &checkpointReadServer{objects: map[string][]byte{
		checkpointfiles.CommitFileName: []byte(generation),
		stateName:                      []byte("runtime"),
		metadataName:                   []byte("metadata"),
		pagesName:                      []byte("pages"),
	}}
	opts, cleanup := checkpointGoferRestoreOpts(t, server)
	defer cleanup()
	stateReader, metadataReader, pagesReader, err := getRestoreReadersForCheckpointGofer(&opts)
	if err != nil {
		t.Fatal(err)
	}
	defer stateReader.Close()
	defer metadataReader.Close()
	defer pagesReader.Close()
	if got, err := io.ReadAll(stateReader); err != nil || string(got) != "runtime" {
		t.Fatalf("runtime reader = %q, %v", got, err)
	}
	if got, err := io.ReadAll(metadataReader); err != nil || string(got) != "metadata" {
		t.Fatalf("metadata reader = %q, %v", got, err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, want := range []string{checkpointfiles.CommitFileName, stateName, metadataName, pagesName} {
		if !slices.Contains(server.opened, want) {
			t.Errorf("committed generation did not open %q; opened %v", want, server.opened)
		}
	}
	for _, legacy := range []string{checkpointfiles.StateFileName, checkpointfiles.PagesMetadataFileName, checkpointfiles.PagesFileName} {
		if slices.Contains(server.opened, legacy) {
			t.Errorf("committed generation opened stale legacy object %q", legacy)
		}
	}
}

func TestGetRestoreReadersForCheckpointGoferLegacyOnlyOnMarkerAbsence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		markerErr error
		wantError bool
	}{
		{name: "absent", markerErr: unix.ENOENT},
		{name: "permission", markerErr: unix.EACCES, wantError: true},
		{name: "transient", markerErr: unix.EIO, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &checkpointReadServer{
				markerErr: tc.markerErr,
				objects: map[string][]byte{
					checkpointfiles.StateFileName:         []byte("legacy-runtime"),
					checkpointfiles.PagesMetadataFileName: []byte("legacy-metadata"),
					checkpointfiles.PagesFileName:         []byte("legacy-pages"),
				},
			}
			opts, cleanup := checkpointGoferRestoreOpts(t, server)
			defer cleanup()
			stateReader, metadataReader, pagesReader, err := getRestoreReadersForCheckpointGofer(&opts)
			if tc.wantError {
				if err == nil {
					stateReader.Close()
					metadataReader.Close()
					pagesReader.Close()
					t.Fatal("non-absence marker failure selected legacy checkpoint")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			stateReader.Close()
			metadataReader.Close()
			pagesReader.Close()
			server.mu.Lock()
			defer server.mu.Unlock()
			if !slices.Contains(server.opened, checkpointfiles.StateFileName) {
				t.Fatalf("absent marker did not select legacy objects: %v", server.opened)
			}
		})
	}
}
