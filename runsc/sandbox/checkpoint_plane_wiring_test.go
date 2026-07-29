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

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/donation"
)

func TestLocalCheckpointPlaneWiringIgnoresCompression(t *testing.T) {
	for _, compression := range []statefile.CompressionLevel{
		statefile.CompressionLevelNone,
		statefile.CompressionLevelFlateBestSpeed,
	} {
		t.Run(string(compression), func(t *testing.T) {
			var save control.SaveOpts
			output, err := setCheckpointOptsFilesForLocalCheckpoint(nil, t.TempDir(), CheckpointOpts{
				Compression: compression,
				SharedBase:  true,
			}, &save)
			if err != nil {
				t.Fatal(err)
			}
			defer output.abort()
			if !save.HavePagesFile {
				t.Fatal("producer allowed MemoryFile bytes into runtime-native stream")
			}
			if !save.SharedBase {
				t.Fatal("shared base was not wired")
			}
			if got, want := len(save.Files), 4; got != want {
				t.Fatalf("file payload count = %d, want %d (runtime, metadata, pages, base)", got, want)
			}
			for i, name := range []string{
				checkpointfiles.StateFileName,
				checkpointfiles.PagesMetadataFileName,
				checkpointfiles.PagesFileName,
			} {
				if got := filepath.Base(output.final[i]); got != name || output.files[i] != save.Files[i] {
					t.Fatalf("plane %q not fixed at payload index %d", name, i)
				}
			}
		})
	}
}

func TestCompressedWorkloadTriggerUsesTransactionalPlanes(t *testing.T) {
	dir := t.TempDir()
	spec := &specs.Spec{Annotations: map[string]string{
		"dev.gvisor.internal.checkpoint.path":        dir,
		"dev.gvisor.internal.checkpoint.compression": string(statefile.CompressionLevelFlateBestSpeed),
	}}
	var donations donation.Agency
	defer donations.Close()
	cmd := exec.Command("runsc")
	s := &Sandbox{}
	if err := s.maybeConfigureSandboxProcessForWorkloadTriggerSave(&config.Config{}, &Args{Spec: spec}, cmd, &donations); err != nil {
		t.Fatal(err)
	}
	donations.Transfer(cmd, 3)
	var saveFDs, publishDirFDs int
	for _, arg := range cmd.Args {
		switch {
		case strings.HasPrefix(arg, "--save-fds="):
			saveFDs++
		case strings.HasPrefix(arg, "--save-publish-dir-fd="):
			publishDirFDs++
		}
	}
	if saveFDs != 3 || publishDirFDs != 1 || len(cmd.ExtraFiles) != 4 {
		t.Fatalf("compressed workload donations: save planes=%d publish dirs=%d extra files=%d, want 3/1/4", saveFDs, publishDirFDs, len(cmd.ExtraFiles))
	}
	for _, name := range []string{
		checkpointfiles.StateFileName,
		checkpointfiles.PagesMetadataFileName,
		checkpointfiles.PagesFileName,
	} {
		staged, err := checkpointfiles.LocalStagingFileName(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, staged)); err != nil {
			t.Fatalf("missing donated staging file %q: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("workload plane %q published before save completion: %v", name, err)
		}
	}
}

func TestCompressedTestAutosaveUsesTransactionalPlanes(t *testing.T) {
	dir := t.TempDir()
	var donations donation.Agency
	defer donations.Close()
	if err := configureTestAutosaveDonations(&config.Config{TestOnlyAutosaveImagePath: dir}, &donations); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("runsc")
	donations.Transfer(cmd, 3)
	var saveFDs, publishDirFDs int
	for _, arg := range cmd.Args {
		switch {
		case strings.HasPrefix(arg, "--save-fds="):
			saveFDs++
		case strings.HasPrefix(arg, "--save-publish-dir-fd="):
			publishDirFDs++
		}
	}
	if saveFDs != 3 || publishDirFDs != 1 {
		t.Fatalf("test autosave donations: save planes=%d publish dirs=%d, want 3/1", saveFDs, publishDirFDs)
	}
}

func TestCheckpointGoferPlaneWiring(t *testing.T) {
	var save control.SaveOpts
	if err := configureRuntimeNativeCheckpointGofer(&save); err != nil {
		t.Fatal(err)
	}
	if !save.HavePagesFile {
		t.Fatal("checkpoint-gofer producer did not split MemoryFile bytes")
	}
	if !checkpointfiles.ValidGeneration(save.CheckpointGeneration) {
		t.Fatalf("invalid checkpoint generation %q", save.CheckpointGeneration)
	}
}
