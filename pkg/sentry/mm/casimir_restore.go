package mm

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

const (
	casimirProtectionRead = 1 << iota
	casimirProtectionWrite
	casimirProtectionExecute
)

const (
	casimirRegionGuard = 1 << iota
	casimirRegionShared
)

type casimirRestoreAction struct {
	addr       hostarch.Addr
	length     uint64
	protection hostarch.AccessType
	unmap      bool
}

// RestoreCasimirMappings binds the authenticated LLIFS mapping table to this
// restored address space. It plans the complete reconciliation while holding
// read locks, rejects any geometry or sharing mismatch, then reapplies exact
// permissions and removes signed guard/unmapped ranges before task resume.
func (mm *MemoryManager) RestoreCasimirMappings(ctx context.Context, regions []pgalloc.CasimirRegion) error {
	if mm == nil || len(regions) == 0 {
		return fmt.Errorf("missing Casimir mapping authority")
	}
	if err := validateCasimirRegions(regions); err != nil {
		return err
	}

	mm.mappingMu.RLock()
	mm.activeMu.RLock()
	var actions []casimirRestoreAction
	var bound bool
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); pseg = pseg.NextSegment() {
		pma := pseg.ValuePtr()
		if pma.file != mm.mf {
			continue
		}
		fileStart := pma.off
		fileEnd := fileStart + uint64(pseg.Range().Length())
		if fileEnd < fileStart {
			mm.activeMu.RUnlock()
			mm.mappingMu.RUnlock()
			return fmt.Errorf("restored Casimir PMA range overflows")
		}
		for fileStart < fileEnd {
			region, ok := casimirRegionAt(regions, fileStart)
			if !ok {
				mm.activeMu.RUnlock()
				mm.mappingMu.RUnlock()
				return fmt.Errorf("restored PMA offset %#x lacks signed mapping", fileStart)
			}
			regionEnd := region.GuestStart + region.Length
			chunkEnd := min(fileEnd, regionEnd)
			chunkLength := chunkEnd - fileStart
			virtualStart := pseg.Start() + hostarch.Addr(fileStart-pma.off)
			vseg := mm.vmas.FindSegment(virtualStart)
			if !vseg.Ok() || uint64(vseg.End()-virtualStart) < chunkLength {
				mm.activeMu.RUnlock()
				mm.mappingMu.RUnlock()
				return fmt.Errorf("restored PMA at %#x is not bound to one complete VMA", virtualStart)
			}
			vma := vseg.ValuePtr()
			unmap := region.State == 3 || region.Flags&casimirRegionGuard != 0
			if !unmap {
				wantPrivate := region.Flags&casimirRegionShared == 0
				if vma.private != wantPrivate {
					mm.activeMu.RUnlock()
					mm.mappingMu.RUnlock()
					return fmt.Errorf("restored VMA at %#x shared/private attribute differs from signed mapping", virtualStart)
				}
			}
			actions = append(actions, casimirRestoreAction{
				addr:       virtualStart,
				length:     chunkLength,
				protection: casimirAccessType(region.Protection),
				unmap:      unmap,
			})
			bound = true
			fileStart = chunkEnd
		}
	}
	mm.activeMu.RUnlock()
	mm.mappingMu.RUnlock()
	if !bound {
		return fmt.Errorf("signed Casimir mapping table binds no restored VMA")
	}

	for _, action := range actions {
		if action.unmap {
			if err := mm.MUnmap(ctx, action.addr, action.length); err != nil {
				return fmt.Errorf("unmap signed Casimir guard range %#x-%#x: %w", action.addr, action.addr+hostarch.Addr(action.length), err)
			}
			continue
		}
		if err := mm.MProtect(action.addr, action.length, action.protection, false); err != nil {
			return fmt.Errorf("reapply signed Casimir protection at %#x-%#x: %w", action.addr, action.addr+hostarch.Addr(action.length), err)
		}
	}
	return nil
}

func validateCasimirRegions(regions []pgalloc.CasimirRegion) error {
	var next uint64
	for _, region := range regions {
		if region.GuestStart != next || region.Length == 0 ||
			region.State < 1 || region.State > 3 ||
			region.Protection&^uint8(7) != 0 ||
			region.Flags&^uint8(3) != 0 ||
			region.GuestStart > ^uint64(0)-region.Length {
			return fmt.Errorf("invalid signed Casimir mapping at %#x", region.GuestStart)
		}
		next += region.Length
	}
	return nil
}

func casimirRegionAt(regions []pgalloc.CasimirRegion, offset uint64) (pgalloc.CasimirRegion, bool) {
	for _, region := range regions {
		if region.GuestStart > offset {
			break
		}
		if offset-region.GuestStart < region.Length {
			return region, true
		}
	}
	return pgalloc.CasimirRegion{}, false
}

func casimirAccessType(protection uint8) hostarch.AccessType {
	return hostarch.AccessType{
		Read:    protection&casimirProtectionRead != 0,
		Write:   protection&casimirProtectionWrite != 0,
		Execute: protection&casimirProtectionExecute != 0,
	}
}
