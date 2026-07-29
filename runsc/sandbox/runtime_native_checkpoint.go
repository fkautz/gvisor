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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
)

// linuxODirect is Linux O_DIRECT. runsc only uses direct checkpoint I/O on
// Linux, but keeping the value local lets the plane transaction tests run on
// non-Linux development hosts.
const linuxODirect = 0x4000

const checkpointTransactionFile = checkpointfiles.LocalTransactionFileName
const checkpointTransactionMagic = checkpointfiles.LocalTransactionMagic

// runtimeNativeCheckpointOutput owns the fixed checkpoint plane inventory.
// Files remain private until publish. checkpoint.img is linked last and is the
// commit point: restore cannot observe a usable checkpoint before every other
// required artifact is durable and visible.
type runtimeNativeCheckpointOutput struct {
	files       []*os.File
	staged      []string
	final       []string
	published   []string
	committed   bool
	aborted     bool
	syncDir     func(string) error
	transaction string
	imagePath   string
}

func newRuntimeNativeCheckpointOutput(imagePath string, direct, sharedBase bool) (_ *runtimeNativeCheckpointOutput, retErr error) {
	if err := recoverRuntimeNativeCheckpointOutput(imagePath); err != nil {
		return nil, err
	}
	names := []string{
		checkpointfiles.StateFileName,
		checkpointfiles.PagesMetadataFileName,
		checkpointfiles.PagesFileName,
	}
	if sharedBase {
		names = append(names, "base.img")
	}
	for _, name := range names {
		final := filepath.Join(imagePath, name)
		if _, err := os.Lstat(final); err == nil {
			return nil, fmt.Errorf("checkpoint artifact %q already exists", final)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("checking checkpoint artifact %q: %w", final, err)
		}
	}

	output := &runtimeNativeCheckpointOutput{
		syncDir:   syncDir,
		imagePath: imagePath,
	}
	defer func() {
		if retErr != nil {
			output.abort()
		}
	}()
	output.transaction = filepath.Join(imagePath, checkpointTransactionFile)
	transaction, err := os.OpenFile(output.transaction, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("creating checkpoint transaction marker: %w", err)
	}
	if _, err := transaction.WriteString(checkpointTransactionMagic); err != nil {
		transaction.Close()
		return nil, fmt.Errorf("writing checkpoint transaction marker: %w", err)
	}
	if err := transaction.Sync(); err != nil {
		transaction.Close()
		return nil, fmt.Errorf("syncing checkpoint transaction marker: %w", err)
	}
	if err := transaction.Close(); err != nil {
		return nil, fmt.Errorf("closing checkpoint transaction marker: %w", err)
	}
	if err := output.syncDir(imagePath); err != nil {
		return nil, fmt.Errorf("syncing checkpoint transaction marker directory: %w", err)
	}
	for _, name := range names {
		stagedName, err := checkpointfiles.LocalStagingFileName(name)
		if err != nil {
			return nil, err
		}
		staged, err := os.OpenFile(filepath.Join(imagePath, stagedName), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("staging checkpoint artifact %q: %w", name, err)
		}
		if direct && name == checkpointfiles.PagesFileName {
			stagedPath := staged.Name()
			if err := staged.Close(); err != nil {
				os.Remove(stagedPath)
				return nil, fmt.Errorf("closing staged pages artifact %q: %w", name, err)
			}
			staged, err = os.OpenFile(stagedPath, os.O_RDWR|linuxODirect, 0)
			if err != nil {
				os.Remove(stagedPath)
				return nil, fmt.Errorf("opening staged pages artifact %q with O_DIRECT: %w", name, err)
			}
		}
		output.files = append(output.files, staged)
		output.staged = append(output.staged, staged.Name())
		output.final = append(output.final, filepath.Join(imagePath, name))
	}
	return output, nil
}

func (o *runtimeNativeCheckpointOutput) publish() error {
	if o.committed {
		return nil
	}
	for i, file := range o.files {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("syncing %q: %w", file.Name(), err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("closing %q: %w", file.Name(), err)
		}
		o.files[i] = nil
	}

	// Publish all non-runtime planes first. The runtime-native stream is the
	// final link and therefore the checkpoint's atomic usability marker.
	for i := 1; i < len(o.staged); i++ {
		if err := os.Link(o.staged[i], o.final[i]); err != nil {
			return fmt.Errorf("publishing %q: %w", o.final[i], err)
		}
		o.published = append(o.published, o.final[i])
	}
	if err := o.syncDir(filepath.Dir(o.final[0])); err != nil {
		return fmt.Errorf("syncing checkpoint directory before runtime commit: %w", err)
	}
	if err := os.Link(o.staged[0], o.final[0]); err != nil {
		return fmt.Errorf("publishing %q: %w", o.final[0], err)
	}
	o.published = append(o.published, o.final[0])
	// This fsync makes checkpoint.img durable strictly after every
	// non-runtime plane directory entry.
	if err := o.syncDir(filepath.Dir(o.final[0])); err != nil {
		return fmt.Errorf("syncing checkpoint directory after runtime commit: %w", err)
	}
	for _, staged := range o.staged {
		if err := os.Remove(staged); err != nil {
			return fmt.Errorf("removing staged artifact %q: %w", staged, err)
		}
	}
	// Make removal of all private staging entries durable while the
	// transaction marker still makes them recoverable after a crash.
	if err := o.syncDir(filepath.Dir(o.final[0])); err != nil {
		return fmt.Errorf("syncing checkpoint directory after staged artifact removal: %w", err)
	}
	if err := os.Remove(o.transaction); err != nil {
		return fmt.Errorf("removing checkpoint transaction marker: %w", err)
	}
	if err := o.syncDir(filepath.Dir(o.final[0])); err != nil {
		return fmt.Errorf("syncing checkpoint directory after transaction cleanup: %w", err)
	}
	o.committed = true
	return nil
}

func (o *runtimeNativeCheckpointOutput) abort() error {
	if o.committed || o.aborted {
		return nil
	}
	var errs []error
	for _, file := range o.files {
		if file != nil {
			errs = append(errs, file.Close())
		}
	}
	for _, staged := range o.staged {
		if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	for _, published := range o.published {
		if err := os.Remove(published); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if o.transaction != "" {
		// Keep the marker durable until all artifact removals are durable, so
		// recovery remains possible after a crash during rollback.
		if err := o.syncDir(o.imagePath); err != nil {
			errs = append(errs, err)
		} else {
			if err := os.Remove(o.transaction); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			} else {
				errs = append(errs, o.syncDir(o.imagePath))
			}
		}
	}
	o.aborted = true
	return errors.Join(errs...)
}

func recoverRuntimeNativeCheckpointOutput(imagePath string) error {
	transaction := filepath.Join(imagePath, checkpointTransactionFile)
	contents, err := os.ReadFile(transaction)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading checkpoint transaction marker: %w", err)
	}
	if string(contents) != checkpointTransactionMagic {
		return fmt.Errorf("checkpoint transaction marker has invalid contents")
	}

	// checkpoint.img is the durable commit point. If it is absent, fixed
	// non-runtime links belong to the abandoned transaction. If it is present,
	// publication completed and only hidden staging state is abandoned.
	if _, err := os.Lstat(filepath.Join(imagePath, checkpointfiles.StateFileName)); os.IsNotExist(err) {
		for _, name := range []string{
			checkpointfiles.PagesMetadataFileName,
			checkpointfiles.PagesFileName,
			"base.img",
		} {
			if err := os.Remove(filepath.Join(imagePath, name)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("recovering abandoned checkpoint artifact %q: %w", name, err)
			}
		}
	} else if err != nil {
		return fmt.Errorf("checking checkpoint commit during recovery: %w", err)
	}

	for _, name := range []string{
		checkpointfiles.StateFileName,
		checkpointfiles.PagesMetadataFileName,
		checkpointfiles.PagesFileName,
		"base.img",
	} {
		staged, err := checkpointfiles.LocalStagingFileName(name)
		if err != nil {
			return err
		}
		match := filepath.Join(imagePath, staged)
		if err := os.Remove(match); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing abandoned checkpoint staging file %q: %w", match, err)
		}
	}
	// Persist all recovery removals before clearing the marker that owns them.
	if err := syncDir(imagePath); err != nil {
		return fmt.Errorf("syncing recovered checkpoint artifacts: %w", err)
	}
	if err := os.Remove(transaction); err != nil {
		return fmt.Errorf("removing abandoned checkpoint transaction marker: %w", err)
	}
	if err := syncDir(imagePath); err != nil {
		return fmt.Errorf("syncing recovered checkpoint directory: %w", err)
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
