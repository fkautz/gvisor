// Copyright 2025 The gVisor Authors.
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

// Package checkpointfiles defines constants used when sentry state is
// checkpointed to multiple files in a directory rather than to an opaque FD.
package checkpointfiles

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/sys/unix"
)

// Plane identifies the producer-owned checkpoint plane containing a file.
// Callers must not construct an inventory and assign plane membership
// themselves: the checkpoint producer owns this fixed mapping.
type Plane uint8

const (
	// RuntimeNativePlane contains opaque sentry state required by restore.
	RuntimeNativePlane Plane = iota
	// MemoryPlane contains MemoryFile metadata and page bytes.
	MemoryPlane
	// FilesystemPlane contains writable filesystem checkpoint payloads.
	FilesystemPlane
)

// Files common to both full and filesystem checkpoints:
const (
	// PagesMetadataFileName is the file in an image-path directory containing
	// MemoryFile metadata.
	PagesMetadataFileName = "pages_meta.img"

	// PagesFileName is the file in an image-path directory containing
	// MemoryFile page contents.
	PagesFileName = "pages.img"
)

// Files specific to full checkpoints:
const (
	// StateFileName is the file in an image-path directory which contains the
	// sentry object graph.
	StateFileName = "checkpoint.img"

	// CommitFileName contains the generation identifier of the latest complete
	// checkpoint-gofer checkpoint. The object is published only after every
	// generation-scoped runtime and memory object has finalized.
	CommitFileName = "checkpoint.commit"

	// LocalTransactionFileName owns fixed local staging entries until they
	// have either been committed or durably removed.
	LocalTransactionFileName = ".checkpoint.transaction"

	// LocalTransactionMagic prevents recovery from treating an unrelated
	// caller-created file as producer-owned transaction state.
	LocalTransactionMagic = "gvisor-runtime-checkpoint-v1\n"
)

// Files specific to filesystem checkpoints (see fscheckpoint package for
// details):
const (
	FSCheckpointManifestFileName = "fscheckpoint.json"
	FSCheckpointMultiTarFileName = "multitar.img"
)

// PlaneForFile returns the producer-owned plane for name.
func PlaneForFile(name string) (Plane, bool) {
	switch name {
	case StateFileName:
		return RuntimeNativePlane, true
	case PagesMetadataFileName, PagesFileName:
		return MemoryPlane, true
	case FSCheckpointManifestFileName, FSCheckpointMultiTarFileName:
		return FilesystemPlane, true
	default:
		return 0, false
	}
}

const generationPrefix = "generations/"

// NewGeneration returns a canonical random 128-bit checkpoint generation.
func NewGeneration() (string, error) {
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return "", fmt.Errorf("generating checkpoint generation: %w", err)
	}
	return hex.EncodeToString(generation[:]), nil
}

// LocalStagingFileName returns the fixed private staging name for a
// producer-owned local checkpoint plane.
func LocalStagingFileName(name string) (string, error) {
	switch name {
	case StateFileName, PagesMetadataFileName, PagesFileName, "base.img":
		return "." + name + ".tmp", nil
	default:
		return "", fmt.Errorf("invalid local checkpoint file %q", name)
	}
}

// GenerationFileName returns a generation-scoped checkpoint-gofer object
// name. generation must be a 128-bit lowercase hexadecimal identifier, and
// name must be owned by the full-checkpoint producer.
func GenerationFileName(generation, name string) (string, error) {
	if !ValidGeneration(generation) {
		return "", fmt.Errorf("invalid checkpoint generation %q", generation)
	}
	switch name {
	case StateFileName, PagesMetadataFileName, PagesFileName:
	default:
		return "", fmt.Errorf("invalid generation checkpoint file %q", name)
	}
	return generationPrefix + generation + "/" + name, nil
}

// ParseGenerationFileName returns the fixed producer-owned file name from a
// generation-scoped checkpoint-gofer object name.
func ParseGenerationFileName(path string) (string, bool) {
	if !strings.HasPrefix(path, generationPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(path, generationPrefix)
	generation, name, ok := strings.Cut(rest, "/")
	if !ok || !ValidGeneration(generation) {
		return "", false
	}
	if generated, err := GenerationFileName(generation, name); err != nil || generated != path {
		return "", false
	}
	return name, true
}

// FullCheckpointFileNames returns the complete runtime and memory plane object
// inventory for generation. An empty generation selects the legacy fixed
// names; a non-empty generation selects only generation-scoped names.
func FullCheckpointFileNames(generation string) (state, pagesMetadata, pages string, err error) {
	if generation == "" {
		return StateFileName, PagesMetadataFileName, PagesFileName, nil
	}
	if state, err = GenerationFileName(generation, StateFileName); err != nil {
		return "", "", "", err
	}
	if pagesMetadata, err = GenerationFileName(generation, PagesMetadataFileName); err != nil {
		return "", "", "", err
	}
	if pages, err = GenerationFileName(generation, PagesFileName); err != nil {
		return "", "", "", err
	}
	return state, pagesMetadata, pages, nil
}

// ValidGeneration reports whether generation is a canonical 128-bit
// lowercase hexadecimal checkpoint generation identifier.
func ValidGeneration(generation string) bool {
	if len(generation) != 32 || strings.ToLower(generation) != generation {
		return false
	}
	decoded, err := hex.DecodeString(generation)
	return err == nil && len(decoded) == 16
}

// ReadCommittedGeneration reads the checkpoint-gofer commit marker opened by
// open. It returns an empty generation only when the marker is authoritatively
// absent. All other open, read, and close errors fail closed so a transient
// marker failure cannot select stale legacy objects.
func ReadCommittedGeneration(open func() (io.ReadCloser, error)) (string, error) {
	r, err := open()
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", nil
		}
		return "", fmt.Errorf("opening checkpoint commit marker: %w", err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(r, 33))
	closeErr := r.Close()
	if readErr != nil || closeErr != nil {
		if errors.Is(readErr, unix.ENOENT) && closeErr == nil {
			return "", nil
		}
		return "", fmt.Errorf("reading checkpoint commit marker: %w", errors.Join(readErr, closeErr))
	}
	generation := string(contents)
	if !ValidGeneration(generation) {
		return "", fmt.Errorf("invalid checkpoint commit generation %q", generation)
	}
	return generation, nil
}

// CommitWriter is a checkpoint-gofer marker that can either be finalized or
// discarded without publishing buffered bytes.
type CommitWriter interface {
	Close() error
	Abort() error
}

// SaveAndCommit drives the Kernel.SaveTo boundary represented by saveTo. The
// marker is finalized only after saveTo succeeds, and is aborted on all save
// failures.
func SaveAndCommit(saveTo func() error, commit CommitWriter) error {
	if err := saveTo(); err != nil {
		if commit == nil {
			return err
		}
		return errors.Join(err, commit.Abort())
	}
	if commit == nil {
		return nil
	}
	if err := commit.Close(); err != nil {
		return fmt.Errorf("publishing checkpoint commit marker: %w", err)
	}
	return nil
}

// FinishLocalTransaction publishes or aborts a local runtime-native checkpoint
// using dirFD. planeFDs must contain runtime, metadata, pages, and optionally
// shared-base FDs in that order. saveErr is returned together with any durable
// rollback failure.
func FinishLocalTransaction(dirFD int, planeFDs []int, saveErr error) error {
	if err := validateLocalTransaction(dirFD); err != nil {
		return errors.Join(saveErr, err)
	}
	names := []string{StateFileName, PagesMetadataFileName, PagesFileName}
	if len(planeFDs) == 4 {
		names = append(names, "base.img")
	} else if len(planeFDs) != 3 {
		return errors.Join(saveErr, fmt.Errorf("got %d local checkpoint planes, want 3 or 4", len(planeFDs)))
	}
	if saveErr != nil {
		return errors.Join(saveErr, rollbackLocalTransaction(dirFD, names, nil))
	}

	for i, planeFD := range planeFDs {
		if err := unix.Fsync(planeFD); err != nil {
			return errors.Join(
				fmt.Errorf("syncing local checkpoint plane %q: %w", names[i], err),
				rollbackLocalTransaction(dirFD, names, nil),
			)
		}
	}

	var published []string
	publish := func(i int) error {
		staged, err := LocalStagingFileName(names[i])
		if err != nil {
			return err
		}
		if err := unix.Linkat(dirFD, staged, dirFD, names[i], 0); err != nil {
			return fmt.Errorf("publishing local checkpoint plane %q: %w", names[i], err)
		}
		published = append(published, names[i])
		return nil
	}
	for i := 1; i < len(names); i++ {
		if err := publish(i); err != nil {
			return errors.Join(err, rollbackLocalTransaction(dirFD, names, published))
		}
	}
	if err := unix.Fsync(dirFD); err != nil {
		return errors.Join(
			fmt.Errorf("syncing local checkpoint directory before runtime commit: %w", err),
			rollbackLocalTransaction(dirFD, names, published),
		)
	}
	if err := publish(0); err != nil {
		return errors.Join(err, rollbackLocalTransaction(dirFD, names, published))
	}
	if err := unix.Fsync(dirFD); err != nil {
		return errors.Join(
			fmt.Errorf("syncing local checkpoint directory after runtime commit: %w", err),
			rollbackLocalTransaction(dirFD, names, published),
		)
	}
	return cleanupLocalTransaction(dirFD, names)
}

func validateLocalTransaction(dirFD int) error {
	markerFD, err := unix.Openat(dirFD, LocalTransactionFileName, unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening local checkpoint transaction marker: %w", err)
	}
	defer unix.Close(markerFD)
	contents := make([]byte, len(LocalTransactionMagic)+1)
	n, err := unix.Read(markerFD, contents)
	if err != nil {
		return fmt.Errorf("reading local checkpoint transaction marker: %w", err)
	}
	if string(contents[:n]) != LocalTransactionMagic {
		return fmt.Errorf("local checkpoint transaction marker has invalid contents")
	}
	return nil
}

func rollbackLocalTransaction(dirFD int, names, published []string) error {
	var errs []error
	for _, name := range published {
		if err := unix.Unlinkat(dirFD, name, 0); err != nil && err != unix.ENOENT {
			errs = append(errs, err)
		}
	}
	for _, name := range names {
		staged, err := LocalStagingFileName(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := unix.Unlinkat(dirFD, staged, 0); err != nil && err != unix.ENOENT {
			errs = append(errs, err)
		}
	}
	if err := unix.Fsync(dirFD); err != nil {
		return errors.Join(append(errs, err)...)
	}
	if err := unix.Unlinkat(dirFD, LocalTransactionFileName, 0); err != nil && err != unix.ENOENT {
		return errors.Join(append(errs, err)...)
	}
	errs = append(errs, unix.Fsync(dirFD))
	return errors.Join(errs...)
}

func cleanupLocalTransaction(dirFD int, names []string) error {
	for _, name := range names {
		staged, err := LocalStagingFileName(name)
		if err != nil {
			return err
		}
		if err := unix.Unlinkat(dirFD, staged, 0); err != nil {
			return fmt.Errorf("removing local checkpoint staging plane %q: %w", name, err)
		}
	}
	if err := unix.Fsync(dirFD); err != nil {
		return fmt.Errorf("syncing local checkpoint staging cleanup: %w", err)
	}
	if err := unix.Unlinkat(dirFD, LocalTransactionFileName, 0); err != nil {
		return fmt.Errorf("removing local checkpoint transaction marker: %w", err)
	}
	if err := unix.Fsync(dirFD); err != nil {
		return fmt.Errorf("syncing local checkpoint transaction cleanup: %w", err)
	}
	return nil
}
