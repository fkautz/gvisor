// Copyright 2024 The gVisor Authors.
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

package boot

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/strace"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/urpc"
)

func getTargetForSaveRestore(l *Loader, files []*fd.FD, resume bool) func(k *kernel.Kernel) {
	var once sync.Once
	return func(k *kernel.Kernel) {
		once.Do(func() {
			publishDir := l.savePublishDir
			l.savePublishDir = nil
			osFiles := make([]*os.File, len(files))
			for i, file := range files {
				var err error
				osFiles[i], err = file.File()
				if err != nil {
					for _, opened := range osFiles[:i] {
						_ = opened.Close()
					}
					err = finishConfiguredSave(files, publishDir, err)
					l.k.OnCheckpointAttempt(err)
					return
				}
			}
			opts, err := control.ConvertToStateSaveOpts(&control.SaveOpts{
				Metadata:      statefile.CompressionLevelFlateBestSpeed.ToMetadata(),
				HavePagesFile: true,
				Resume:        resume,
				FilePayload:   urpc.FilePayload{Files: osFiles},
			})
			if err != nil {
				for _, file := range osFiles {
					_ = file.Close()
				}
				err = finishConfiguredSave(files, publishDir, err)
				l.k.OnCheckpointAttempt(err)
				return
			}
			opts.Autosave = true
			defer opts.Close()
			_ = l.saveWithOptsAndFinalize(opts, &control.SaveRestoreExecOpts{}, func(saveErr error) error {
				return finishConfiguredSave(files, publishDir, saveErr)
			})
		})
	}
}

// enableAutosave enables auto save restore in syscall tests.
func enableAutosave(l *Loader, isResume bool, files []*fd.FD) error {
	if len(files) != 3 {
		return fmt.Errorf("unexpected autosave plane count %d, want 3", len(files))
	}
	target := getTargetForSaveRestore(l, files, isResume)

	for _, table := range kernel.SyscallTables() {
		sys, ok := strace.Lookup(table.OS, table.Arch)
		if !ok {
			continue
		}
		if err := configureInitSyscall(table, sys, "init_module", kernel.ExternalAfterEnable); err != nil {
			return err
		}
		// Set external args to our closure above.
		table.External = target
	}

	return nil
}

// configureInitSyscall sets the trigger for the S/R syscall tests and the callback
// method to be called after the sycall is executed.
func configureInitSyscall(table *kernel.SyscallTable, sys strace.SyscallMap, initSyscall string, syscallFlag uint32) error {
	sl := make(map[uintptr]bool)
	sysno, ok := sys.ConvertToSysno(initSyscall)
	if !ok {
		return fmt.Errorf("syscall %q not found", initSyscall)
	}
	sl[sysno] = true
	log.Infof("sysno %v name %v", sysno, initSyscall)
	table.FeatureEnable.Enable(syscallFlag, sl, false)
	table.ExternalFilterBefore = func(*kernel.Task, uintptr, arch.SyscallArguments) bool {
		return false
	}
	// Sets ExternalFilterAfter to true which calls the closure assigned to
	// External after the syscall is executed.
	table.ExternalFilterAfter = func(*kernel.Task, uintptr, arch.SyscallArguments) bool {
		return true
	}
	return nil
}
