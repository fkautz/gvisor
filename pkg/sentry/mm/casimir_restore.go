package mm

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

const (
	casimirStateMappedData = 1
	casimirStateMappedZero = 2
	casimirStateUnmapped   = 3

	casimirRegionGuard  = 1
	casimirRegionShared = 2
)

// CaptureCasimirAddressSpace derives LLML2 geometry from the MemoryManager's
// authoritative VMA and PMA graphs. In particular, it records lazy anonymous
// ranges for which no PMA exists and explicit gaps between VMAs.
func (mm *MemoryManager) CaptureCasimirAddressSpace(ctx context.Context, identity pgalloc.CasimirAuthorityID) (pgalloc.CasimirAddressSpace, error) {
	if mm == nil {
		return pgalloc.CasimirAddressSpace{}, fmt.Errorf("missing MemoryManager")
	}
	out := pgalloc.CasimirAddressSpace{
		Identity: identity,
		MinAddr:  uint64(mm.layout.MinAddr),
		MaxAddr:  uint64(mm.layout.MaxAddr),
	}
	if out.MinAddr >= out.MaxAddr {
		return pgalloc.CasimirAddressSpace{}, fmt.Errorf("invalid address-space bounds %#x-%#x", out.MinAddr, out.MaxAddr)
	}

	mm.mappingMu.RLock()
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	defer mm.mappingMu.RUnlock()

	cursor := mm.layout.MinAddr
	for vseg := mm.vmas.FirstSegment(); vseg.Ok(); vseg = vseg.NextSegment() {
		if vseg.End() <= mm.layout.MinAddr || vseg.Start() >= mm.layout.MaxAddr {
			continue
		}
		start := max(vseg.Start(), mm.layout.MinAddr)
		end := min(vseg.End(), mm.layout.MaxAddr)
		v := vseg.ValuePtr()
		if cursor < start {
			flags := uint8(0)
			if v.growsDown {
				flags = casimirRegionGuard
			}
			appendCasimirRegion(&out.Regions, pgalloc.CasimirRegion{
				GuestStart: uint64(cursor), Length: uint64(start - cursor),
				State: casimirStateUnmapped, Flags: flags,
			})
		}
		for at := start; at < end; {
			next := end
			region := pgalloc.CasimirRegion{
				GuestStart: uint64(at),
				Protection: casimirProtection(v.realPerms),
			}
			if !v.private {
				region.Flags |= casimirRegionShared
			}
			if v.realPerms == (hostarch.AccessType{}) {
				region.State = casimirStateUnmapped
			} else if v.mappable != nil {
				region.State = casimirStateMappedData
				region.BackingKind = pgalloc.CasimirBackingCheckpointObject
				region.Backing = mappingIdentity(v, ctx)
				region.ObjectOffset = v.off + uint64(at-vseg.Start())
			} else if pseg := mm.pmas.FindSegment(at); pseg.Ok() {
				if pseg.End() < next {
					next = pseg.End()
				}
				p := pseg.ValuePtr()
				region.State = casimirStateMappedData
				region.ObjectOffset = p.off + uint64(at-pseg.Start())
				if p.file == mm.mf {
					region.BackingKind = pgalloc.CasimirBackingBaseMemory
					region.Backing = sha256.Sum256([]byte("gvisor.main-memory-file.v1"))
				} else {
					region.BackingKind = pgalloc.CasimirBackingCheckpointObject
					backing, ok := p.file.(*pgalloc.MemoryFile)
					if !ok || !backing.ResourceID().Ok() {
						return pgalloc.CasimirAddressSpace{}, fmt.Errorf("non-main PMA at %#x lacks stable checkpoint ResourceID", at)
					}
					region.Backing = sha256.Sum256([]byte("gvisor.memory-file.v1:" + backing.ResourceID().String()))
				}
			} else {
				region.State = casimirStateMappedZero
				if gap := mm.pmas.FindGap(at); gap.Ok() && gap.End() < next {
					next = gap.End()
				}
			}
			region.Length = uint64(next - at)
			appendCasimirRegion(&out.Regions, region)
			at = next
		}
		cursor = end
	}
	if cursor < mm.layout.MaxAddr {
		appendCasimirRegion(&out.Regions, pgalloc.CasimirRegion{
			GuestStart: uint64(cursor), Length: uint64(mm.layout.MaxAddr - cursor),
			State: casimirStateUnmapped,
		})
	}
	if len(out.Regions) == 0 {
		return pgalloc.CasimirAddressSpace{}, fmt.Errorf("address space has no canonical tiling")
	}
	return out, nil
}

// RestoreCasimirMappings fails closed unless the restored authoritative VMA
// graph is byte-for-byte equivalent to the signed LLML2 address space.
func (mm *MemoryManager) RestoreCasimirMappings(ctx context.Context, signed pgalloc.CasimirAddressSpace) error {
	got, err := mm.CaptureCasimirAddressSpace(ctx, signed.Identity)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, signed) {
		return fmt.Errorf("restored VMA geometry differs from signed LLML2 authority")
	}
	mm.casimirIdentity = signed.Identity
	return nil
}

func mappingIdentity(v *vma, ctx context.Context) pgalloc.CasimirAuthorityID {
	name := v.name
	var device, inode uint64
	if v.id != nil {
		if name == "" {
			name = v.id.MappedName(ctx)
		}
		device = v.id.DeviceID()
		inode = v.id.InodeID()
	}
	return sha256.Sum256([]byte(fmt.Sprintf("gvisor.mapping.v1:%T:%d:%d:%s", v.mappable, device, inode, name)))
}

func casimirProtection(at hostarch.AccessType) uint8 {
	var out uint8
	if at.Read {
		out |= 1
	}
	if at.Write {
		out |= 2
	}
	if at.Execute {
		out |= 4
	}
	return out
}

func appendCasimirRegion(regions *[]pgalloc.CasimirRegion, next pgalloc.CasimirRegion) {
	if next.Length == 0 {
		return
	}
	if n := len(*regions); n != 0 {
		last := &(*regions)[n-1]
		if last.GuestStart+last.Length == next.GuestStart &&
			last.State == next.State && last.BackingKind == next.BackingKind &&
			last.Backing == next.Backing && last.Protection == next.Protection &&
			last.Flags == next.Flags &&
			(last.State != casimirStateMappedData || last.ObjectOffset+last.Length == next.ObjectOffset) {
			last.Length += next.Length
			return
		}
	}
	*regions = append(*regions, next)
}
