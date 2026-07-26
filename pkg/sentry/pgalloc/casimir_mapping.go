package pgalloc

import "slices"

// CasimirAuthorityID is a stable identity in the signed LLML2 authority.
type CasimirAuthorityID [32]byte

// CasimirBackingKind identifies the authoritative source for mapped bytes.
type CasimirBackingKind uint8

const (
	CasimirBackingNone CasimirBackingKind = iota
	CasimirBackingBaseMemory
	CasimirBackingCheckpointObject
)

// CasimirRegion is one signed LLIFS mapping record retained from the
// authenticated restore data plane. GuestStart addresses the canonical main
// MemoryFile; Protection and Flags are applied to every restored guest VMA
// backed by the corresponding file range before tasks resume.
type CasimirRegion struct {
	GuestStart   uint64             `json:"guest_start"`
	Length       uint64             `json:"length"`
	State        uint8              `json:"state"`
	BackingKind  CasimirBackingKind `json:"backing_kind"`
	Backing      CasimirAuthorityID `json:"backing_id"`
	ObjectOffset uint64             `json:"object_offset"`
	Protection   uint8              `json:"protection"`
	Flags        uint8              `json:"flags"`
}

// CasimirAddressSpace is one complete virtual address space in LLML2.
type CasimirAddressSpace struct {
	Identity CasimirAuthorityID `json:"identity"`
	MinAddr  uint64             `json:"min_addr"`
	MaxAddr  uint64             `json:"max_addr"`
	Regions  []CasimirRegion    `json:"regions"`
}

// CasimirLayout is the signed, versioned LLML2 VMA authority.
type CasimirLayout struct {
	Version       uint16                `json:"version"`
	PageSize      uint32                `json:"page_size"`
	AddressSpaces []CasimirAddressSpace `json:"address_spaces"`
}

// Clone returns an owned copy.
func (l CasimirLayout) Clone() CasimirLayout {
	out := l
	out.AddressSpaces = slices.Clone(l.AddressSpaces)
	for i := range out.AddressSpaces {
		out.AddressSpaces[i].Regions = slices.Clone(l.AddressSpaces[i].Regions)
	}
	return out
}

// CasimirMappings returns the signed layout consumed before the MemoryFile
// fault service started.
func (f *MemoryFile) CasimirMappings() (CasimirLayout, bool) {
	if f == nil || f.casimirFaults.Load() == 0 || len(f.casimirMappings.AddressSpaces) == 0 {
		return CasimirLayout{}, false
	}
	return f.casimirMappings.Clone(), true
}
