package boot

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/urpc"
)

// RestoreOpts contains options related to restoring a container's file system.
type RestoreOpts struct {
	// FilePayload contains, in order:
	// 1. checkpoint state file.
	// 2. optional checkpoint pages metadata file.
	// 3. optional checkpoint pages file.
	// 4. optional platform device file.
	urpc.FilePayload
	HavePagesFile  bool
	HaveDeviceFile bool
	Background     bool

	// HaveBaseFile indicates a shared base memory image is present at
	// BaseFileIndex in FilePayload (GVISOR-3 C1); BaseFileBytes is its size.
	HaveBaseFile              bool
	BaseFileIndex             int
	BaseFileBytes             uint64
	HaveCasimirFaultBaseFile  bool
	CasimirFaultBaseFileIndex int
	HaveCasimirDataFile       bool
	CasimirDataFileIndex      int

	// If UseCheckpointGofer is true, the first file in FilePayload is a Unix
	// domain socket connected to a URPC server implementing
	// stateipc.AsyncFileServer and providing checkpoint files. In this case,
	// RestoreOpts.HavePagesFile is unknown and must be determined by
	// containerManager.Restore.
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`
}

func validateCasimirRestoreCapabilities(o *RestoreOpts) error {
	if o.HaveCasimirFaultBaseFile != o.HaveCasimirDataFile {
		return fmt.Errorf("Casimir fault base and data capabilities must be provided together")
	}
	if !o.HaveCasimirFaultBaseFile {
		return nil
	}
	if !o.HaveBaseFile || !o.HavePagesFile {
		return fmt.Errorf("one-shot Casimir fault base requires shared base and async pages")
	}
	indices := []int{o.BaseFileIndex, o.CasimirFaultBaseFileIndex, o.CasimirDataFileIndex}
	for _, index := range indices {
		if index < 0 || index >= len(o.Files) {
			return fmt.Errorf("Casimir restore capability index %d is out of bounds", index)
		}
	}
	if indices[0] == indices[1] || indices[0] == indices[2] || indices[1] == indices[2] {
		return fmt.Errorf("Casimir restore capabilities must use distinct payload descriptors")
	}
	return nil
}
