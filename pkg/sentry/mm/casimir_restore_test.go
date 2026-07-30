package mm

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestCaptureCasimirAddressSpaceIncludesLazyRangesAndGaps(t *testing.T) {
	ctx := contexttest.Context(t)
	manager := testMemoryManager(ctx, t)
	defer manager.DecUsers(ctx)
	addr, err := manager.MMap(ctx, memmap.MMapOpts{
		Length: hostarch.PageSize * 2, Private: true,
		Perms: hostarch.ReadWrite, MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap() error = %v", err)
	}
	if n, err := manager.CopyOut(ctx, addr, []byte{1}, usermem.IOOpts{}); err != nil || n != 1 {
		t.Fatalf("populate first page = (%d, %v)", n, err)
	}
	identity := pgalloc.CasimirAuthorityID{1}
	layout, err := manager.CaptureCasimirAddressSpace(ctx, identity)
	if err != nil {
		t.Fatalf("CaptureCasimirAddressSpace() error = %v", err)
	}
	var haveData, haveGap bool
	for _, region := range layout.Regions {
		switch region.State {
		case casimirStateMappedData:
			haveData = region.BackingKind == pgalloc.CasimirBackingBaseMemory
		case casimirStateUnmapped:
			haveGap = true
		}
	}
	if !haveData || !haveGap {
		t.Fatalf("captured regions omit authority: data=%t gap=%t: %+v", haveData, haveGap, layout.Regions)
	}
	if err := manager.RestoreCasimirMappings(ctx, layout); err != nil {
		t.Fatalf("exact restored layout rejected: %v", err)
	}
	if manager.casimirIdentity != identity {
		t.Fatalf("restored Casimir identity = %x, want %x", manager.casimirIdentity, identity)
	}
	layout.Regions[0].Length += hostarch.PageSize
	if err := manager.RestoreCasimirMappings(ctx, layout); err == nil {
		t.Fatal("mutated signed layout accepted")
	}
}
