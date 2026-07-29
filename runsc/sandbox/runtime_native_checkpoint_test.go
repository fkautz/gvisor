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
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/state/statefile"
)

func TestRuntimeNativeCheckpointPlanesAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	output, err := newRuntimeNativeCheckpointOutput(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer output.abort()

	runtimeSentinel := []byte("required-runtime-native-state")
	memoryMetadataSentinel := []byte("memory-metadata-must-not-enter-runtime")
	memoryPagesSentinel := []byte("memory-pages-must-not-enter-runtime")
	filesystemSentinel := []byte("filesystem-payload-must-not-enter-runtime")
	const requiredMetadataKey = "fork_runtime_native"
	runtimeWriter, err := statefile.NewWriter(
		struct{ io.Writer }{output.files[0]},
		nil,
		map[string]string{
			"compression":       string(statefile.CompressionLevelFlateBestSpeed),
			requiredMetadataKey: "required",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeWriter.Write(runtimeSentinel); err != nil {
		t.Fatal(err)
	}
	if err := runtimeWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for i, data := range [][]byte{memoryMetadataSentinel, memoryPagesSentinel} {
		fileIndex := i + 1
		if _, err := output.files[fileIndex].Write(data); err != nil {
			t.Fatalf("writing plane %d: %v", fileIndex, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointfiles.FSCheckpointMultiTarFileName), filesystemSentinel, 0644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		checkpointfiles.StateFileName,
		checkpointfiles.PagesMetadataFileName,
		checkpointfiles.PagesFileName,
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%q published before checkpoint completed: %v", name, err)
		}
	}
	if err := output.publish(); err != nil {
		t.Fatal(err)
	}

	runtimeState, err := os.ReadFile(filepath.Join(dir, checkpointfiles.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{memoryMetadataSentinel, memoryPagesSentinel, filesystemSentinel} {
		if bytes.Contains(runtimeState, forbidden) {
			t.Fatalf("non-runtime sentinel %q entered runtime-native stream", forbidden)
		}
	}
	runtimeReader, metadata, err := statefile.NewReader(io.NopCloser(bytes.NewReader(runtimeState)), nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := io.ReadAll(runtimeReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeReader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, runtimeSentinel) {
		t.Fatalf("runtime-native round trip = %q, want %q", roundTrip, runtimeSentinel)
	}
	if got := metadata[requiredMetadataKey]; got != "required" {
		t.Fatalf("required runtime metadata = %q, want %q", got, "required")
	}
	if info, err := os.Stat(filepath.Join(dir, checkpointfiles.StateFileName)); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("runtime-native mode = %#o, want restrictive %#o", got, os.FileMode(0600))
	}

	for name, want := range map[string]checkpointfiles.Plane{
		checkpointfiles.StateFileName:                checkpointfiles.RuntimeNativePlane,
		checkpointfiles.PagesMetadataFileName:        checkpointfiles.MemoryPlane,
		checkpointfiles.PagesFileName:                checkpointfiles.MemoryPlane,
		checkpointfiles.SharedBaseFileName:           checkpointfiles.MemoryPlane,
		checkpointfiles.CasimirLayoutFileName:        checkpointfiles.MemoryPlane,
		checkpointfiles.FSCheckpointManifestFileName: checkpointfiles.FilesystemPlane,
		checkpointfiles.FSCheckpointMultiTarFileName: checkpointfiles.FilesystemPlane,
	} {
		if got, ok := checkpointfiles.PlaneForFile(name); !ok || got != want {
			t.Errorf("PlaneForFile(%q) = (%v, %t), want (%v, true)", name, got, ok, want)
		}
	}
}

func TestRuntimeNativeCommitFollowsDurableMemoryPlanes(t *testing.T) {
	dir := t.TempDir()
	output, err := newRuntimeNativeCheckpointOutput(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	output.syncDir = func(string) error {
		return errors.New("injected pre-commit directory sync failure")
	}
	if err := output.publish(); err == nil {
		t.Fatal("publish succeeded without durable memory plane entries")
	}
	if _, err := os.Stat(filepath.Join(dir, checkpointfiles.StateFileName)); !os.IsNotExist(err) {
		t.Fatalf("runtime commit became visible before memory plane fsync: %v", err)
	}
	output.abort()
}

func TestRuntimeNativeSuccessfulCleanupIsDurableBeforeMarkerRemoval(t *testing.T) {
	dir := t.TempDir()
	output, err := newRuntimeNativeCheckpointOutput(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	var syncs int
	output.syncDir = func(string) error {
		syncs++
		switch syncs {
		case 3:
			for _, staged := range output.staged {
				if _, err := os.Lstat(staged); !os.IsNotExist(err) {
					t.Errorf("staged entry %q remained at cleanup sync: %v", staged, err)
				}
			}
			if _, err := os.Lstat(output.transaction); err != nil {
				t.Errorf("transaction marker removed before staged cleanup became durable: %v", err)
			}
		case 4:
			if _, err := os.Lstat(output.transaction); !os.IsNotExist(err) {
				t.Errorf("transaction marker remained at final sync: %v", err)
			}
		}
		return nil
	}
	if err := output.publish(); err != nil {
		t.Fatal(err)
	}
	if syncs != 4 {
		t.Fatalf("publication directory sync count = %d, want 4", syncs)
	}
}

func TestRuntimeNativeCheckpointCancellationPublishesNothing(t *testing.T) {
	dir := t.TempDir()
	output, err := newRuntimeNativeCheckpointOutput(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := output.files[0].Write([]byte("partial-runtime-state")); err != nil {
		t.Fatal(err)
	}
	output.abort()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled checkpoint left artifacts: %v", entries)
	}
}

func TestRuntimeNativeCheckpointFailurePublishesNothing(t *testing.T) {
	dir := t.TempDir()
	output, err := newRuntimeNativeCheckpointOutput(dir, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// Model a producer/write failure before publication.
	if err := output.files[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.publish(); err == nil {
		t.Fatal("publish succeeded with a closed runtime-native stream")
	}
	output.abort()

	for _, name := range []string{
		checkpointfiles.StateFileName,
		checkpointfiles.PagesMetadataFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.SharedBaseFileName,
		checkpointfiles.CasimirLayoutFileName,
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("failed checkpoint published %q: %v", name, err)
		}
	}
}

func TestRuntimeNativeCheckpointPublishCollisionRollsBack(t *testing.T) {
	dir := t.TempDir()
	output, err := newRuntimeNativeCheckpointOutput(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	collision := filepath.Join(dir, checkpointfiles.PagesFileName)
	if err := os.WriteFile(collision, []byte("independent-writer"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := output.publish(); err == nil {
		t.Fatal("publish succeeded over an existing plane artifact")
	}
	output.abort()

	got, err := os.ReadFile(collision)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("independent-writer"); !bytes.Equal(got, want) {
		t.Fatalf("collision file = %q, want %q", got, want)
	}
	for _, name := range []string{checkpointfiles.StateFileName, checkpointfiles.PagesMetadataFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("failed publication left %q: %v", name, err)
		}
	}
}

func TestRuntimeNativeCheckpointRecoversAbandonedGeneration(t *testing.T) {
	dir := t.TempDir()
	output, err := newRuntimeNativeCheckpointOutput(dir, false, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(output.staged); i++ {
		if err := os.Link(output.staged[i], output.final[i]); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range output.files {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := recoverRuntimeNativeCheckpointOutput(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("recovery left abandoned generation artifacts: %v", entries)
	}
}

func TestRuntimeNativeCheckpointRejectsUnownedRecoveryMarker(t *testing.T) {
	dir := t.TempDir()
	pages := filepath.Join(dir, checkpointfiles.PagesFileName)
	if err := os.WriteFile(pages, []byte("caller-owned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointTransactionFile), []byte("not-gvisor"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newRuntimeNativeCheckpointOutput(dir, false, false); err == nil {
		t.Fatal("unowned transaction marker admitted")
	}
	got, err := os.ReadFile(pages)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("caller-owned")) {
		t.Fatalf("recovery modified caller-owned pages: %q", got)
	}
}

func TestCheckpointGenerationNamesAreProducerOwned(t *testing.T) {
	const generation = "00112233445566778899aabbccddeeff"
	for _, name := range []string{
		checkpointfiles.StateFileName,
		checkpointfiles.PagesMetadataFileName,
		checkpointfiles.PagesFileName,
	} {
		generated, err := checkpointfiles.GenerationFileName(generation, name)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := checkpointfiles.ParseGenerationFileName(generated); !ok || got != name {
			t.Fatalf("ParseGenerationFileName(%q) = (%q, %t), want (%q, true)", generated, got, ok, name)
		}
	}
	for _, invalid := range []string{
		"",
		"00112233445566778899AABBCCDDEEFF",
		"../00112233445566778899aabbccddee",
		"00112233445566778899aabbccddeeff/extra",
	} {
		if checkpointfiles.ValidGeneration(invalid) {
			t.Errorf("ValidGeneration(%q) = true", invalid)
		}
	}
	if _, err := checkpointfiles.GenerationFileName(generation, checkpointfiles.FSCheckpointMultiTarFileName); err == nil {
		t.Fatal("filesystem payload admitted to runtime generation")
	}
}
