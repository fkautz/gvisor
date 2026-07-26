package pgalloc

import "slices"

// CasimirRegion is one signed LLIFS mapping record retained from the
// authenticated restore data plane. GuestStart addresses the canonical main
// MemoryFile; Protection and Flags are applied to every restored guest VMA
// backed by the corresponding file range before tasks resume.
type CasimirRegion struct {
	GuestStart uint64 `json:"guest_start"`
	Length     uint64 `json:"length"`
	State      uint8  `json:"state"`
	Protection uint8  `json:"protection"`
	Flags      uint8  `json:"flags"`
}

// CasimirMappings returns an owned copy of the signed mapping table consumed
// before the MemoryFile fault service started.
func (f *MemoryFile) CasimirMappings() ([]CasimirRegion, bool) {
	if f == nil || f.casimirFaults.Load() == 0 || len(f.casimirMappings) == 0 {
		return nil, false
	}
	return slices.Clone(f.casimirMappings), true
}
