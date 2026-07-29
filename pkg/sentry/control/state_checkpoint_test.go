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

package control

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/state/stateipc"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

const checkpointGenerationForTest = "00112233445566778899aabbccddeeff"

type checkpointObjectServer struct {
	mu      sync.Mutex
	objects map[string][]byte
	opened  []string
}

func (*checkpointObjectServer) Destroy() {}

func (*checkpointObjectServer) OpenRead(string) (stateio.AsyncReader, error) {
	return nil, fmt.Errorf("unexpected read")
}

func (s *checkpointObjectServer) OpenWrite(path string) (stateio.AsyncWriter, error) {
	s.mu.Lock()
	s.opened = append(s.opened, path)
	s.mu.Unlock()
	var staged bytes.Buffer
	return &replacingAsyncWriter{
		AsyncWriter: stateio.NewIOWriter(&staged, 4096, 1, 1),
		finalize: func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.objects[path] = bytes.Clone(staged.Bytes())
		},
	}, nil
}

type replacingAsyncWriter struct {
	stateio.AsyncWriter
	finalize func()
}

func (w *replacingAsyncWriter) Finalize() error {
	if err := w.AsyncWriter.Finalize(); err != nil {
		return err
	}
	w.finalize()
	return nil
}

func TestCheckpointGoferGenerationObjectsAndCommitReplacement(t *testing.T) {
	objects := &checkpointObjectServer{
		objects: map[string][]byte{
			checkpointfiles.CommitFileName: []byte("ffeeddccbbaa99887766554433221100"),
		},
	}
	usrv := urpc.NewServer()
	server, err := stateipc.NewAsyncFileServer(objects)
	if err != nil {
		t.Fatal(err)
	}
	usrv.Register(server)
	clientSock, serverSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatal(err)
	}
	usrv.StartHandling(serverSock)
	defer usrv.Stop(time.Second)
	clientFD, err := clientSock.Release()
	if err != nil {
		t.Fatal(err)
	}
	clientFile := os.NewFile(uintptr(clientFD), "checkpoint-gofer-test")
	defer clientFile.Close()

	opts, err := ConvertToStateSaveOpts(&SaveOpts{
		HavePagesFile:        true,
		UseCheckpointGofer:   true,
		CheckpointGeneration: checkpointGenerationForTest,
		FilePayload:          urpc.FilePayload{Files: []*os.File{clientFile}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer opts.Close()

	stateName, metadataName, pagesName, err := checkpointfiles.FullCheckpointFileNames(checkpointGenerationForTest)
	if err != nil {
		t.Fatal(err)
	}
	for writer, data := range map[interface{ Write([]byte) (int, error) }][]byte{
		opts.Destination:   []byte("runtime"),
		opts.PagesMetadata: []byte("memory-metadata"),
	} {
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := opts.Destination.(interface{ Close() error }).Close(); err != nil {
		t.Fatal(err)
	}
	opts.Destination = nil
	if err := opts.PagesMetadata.Close(); err != nil {
		t.Fatal(err)
	}
	opts.PagesMetadata = nil
	if err := opts.PagesFile.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err := opts.PagesFile.Close(); err != nil {
		t.Fatal(err)
	}
	opts.PagesFile = nil

	objects.mu.Lock()
	if got := string(objects.objects[checkpointfiles.CommitFileName]); got == checkpointGenerationForTest {
		objects.mu.Unlock()
		t.Fatal("commit marker replaced before all checkpoint planes completed")
	}
	for _, name := range []string{stateName, metadataName, pagesName} {
		if _, ok := objects.objects[name]; !ok {
			objects.mu.Unlock()
			t.Fatalf("generation object %q was not finalized", name)
		}
	}
	objects.mu.Unlock()

	if err := opts.CheckpointCommit.Close(); err != nil {
		t.Fatal(err)
	}
	opts.CheckpointCommit = nil
	objects.mu.Lock()
	defer objects.mu.Unlock()
	if got := string(objects.objects[checkpointfiles.CommitFileName]); got != checkpointGenerationForTest {
		t.Fatalf("commit marker = %q, want %q", got, checkpointGenerationForTest)
	}
	wantOpened := []string{stateName, metadataName, pagesName, checkpointfiles.CommitFileName}
	if fmt.Sprint(objects.opened) != fmt.Sprint(wantOpened) {
		t.Fatalf("opened objects = %v, want %v", objects.opened, wantOpened)
	}
}
