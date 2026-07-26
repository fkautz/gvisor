package mm

import (
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestRestoreCasimirMappingsReappliesProtectionBeforeAccess(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	addr, fileOffset := mapCasimirTestPage(t, ctx, mm, hostarch.AnyAccess)

	regions := casimirTestRegions(fileOffset, pgalloc.CasimirRegion{
		GuestStart: fileOffset,
		Length:     hostarch.PageSize,
		State:      1,
		Protection: 1,
	})
	if err := mm.RestoreCasimirMappings(ctx, regions); err != nil {
		t.Fatalf("RestoreCasimirMappings() error = %v", err)
	}
	var got hostarch.AccessType
	mm.ReadMapsDataInto(ctx, func(start, end hostarch.Addr, permissions hostarch.AccessType, _ string, _ uint64, _, _ uint32, _ uint64, _ string) {
		if start <= addr && addr < end {
			got = permissions
		}
	})
	if got != hostarch.Read {
		t.Fatalf("restored permissions = %v, want read-only", got)
	}
}

func TestRestoreCasimirMappingsKeepsMappedZeroAndUnmapsGuardNatively(t *testing.T) {
	ctx := contexttest.Context(t)

	zeroMM := testMemoryManager(ctx, t)
	zeroAddr, zeroOffset := mapCasimirTestPage(t, ctx, zeroMM, hostarch.ReadWrite)
	if err := zeroMM.RestoreCasimirMappings(ctx, casimirTestRegions(zeroOffset, pgalloc.CasimirRegion{
		GuestStart: zeroOffset,
		Length:     hostarch.PageSize,
		State:      2,
		Protection: 1,
	})); err != nil {
		t.Fatalf("restore mapped-zero: %v", err)
	}
	if n, err := zeroMM.CopyIn(ctx, zeroAddr, make([]byte, 1), usermem.IOOpts{}); err != nil || n != 1 {
		t.Fatalf("mapped-zero native read = (%d, %v), want mapped zero byte", n, err)
	}
	zeroMM.DecUsers(ctx)

	guardMM := testMemoryManager(ctx, t)
	guardAddr, guardOffset := mapCasimirTestPage(t, ctx, guardMM, hostarch.ReadWrite)
	if err := guardMM.RestoreCasimirMappings(ctx, casimirTestRegions(guardOffset, pgalloc.CasimirRegion{
		GuestStart: guardOffset,
		Length:     hostarch.PageSize,
		State:      3,
		Flags:      1,
	})); err != nil {
		t.Fatalf("restore guard: %v", err)
	}
	if n, err := guardMM.CopyIn(ctx, guardAddr, make([]byte, 1), usermem.IOOpts{}); err == nil || n != 0 {
		t.Fatalf("guard native read = (%d, %v), want unmapped fault", n, err)
	}
	guardMM.DecUsers(ctx)
}

func TestRestoreCasimirMappingsRejectsSharedPrivateMismatch(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	_, fileOffset := mapCasimirTestPage(t, ctx, mm, hostarch.ReadWrite)
	if err := mm.RestoreCasimirMappings(ctx, casimirTestRegions(fileOffset, pgalloc.CasimirRegion{
		GuestStart: fileOffset,
		Length:     hostarch.PageSize,
		State:      1,
		Protection: 3,
		Flags:      2,
	})); err == nil {
		t.Fatal("private restored VMA accepted signed shared attribute")
	}
}

func mapCasimirTestPage(t *testing.T, ctx context.Context, mm *MemoryManager, perms hostarch.AccessType) (hostarch.Addr, uint64) {
	t.Helper()
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    perms,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap() error = %v", err)
	}
	if n, err := mm.CopyOut(ctx, addr, []byte{0}, usermem.IOOpts{}); err != nil || n != 1 {
		t.Fatalf("populate mapped page = (%d, %v)", n, err)
	}
	mm.activeMu.RLock()
	pseg := mm.pmas.FindSegment(addr)
	if !pseg.Ok() {
		mm.activeMu.RUnlock()
		t.Fatal("populated mapping has no PMA")
	}
	offset := pseg.ValuePtr().off + uint64(addr-pseg.Start())
	mm.activeMu.RUnlock()
	return addr, offset
}

func casimirTestRegions(offset uint64, region pgalloc.CasimirRegion) []pgalloc.CasimirRegion {
	if offset == 0 {
		return []pgalloc.CasimirRegion{region}
	}
	return []pgalloc.CasimirRegion{
		{GuestStart: 0, Length: offset, State: 3},
		region,
	}
}
