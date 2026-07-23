// Copyright 2024 The gVisor Authors.
// LLIFS GVISOR-3 S1b: copy-on-write semantics of a shared base file.
package pgalloc

import (
	"bytes"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

func TestSharedBaseCOW(t *testing.T) {
	const baseLen = 4 << 20 // 4 MiB, well under the 1 GiB chunk -> exercises finer mapping
	base, err := os.CreateTemp("", "llifs-base-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(base.Name())
	defer base.Close()
	pat := make([]byte, baseLen)
	for i := range pat {
		pat[i] = byte(i*131 + 7)
	}
	if _, err := base.WriteAt(pat, 0); err != nil {
		t.Fatal(err)
	}

	mk := func() *MemoryFile {
		b, err := os.CreateTemp("", "llifs-backing-*")
		if err != nil {
			t.Fatal(err)
		}
		os.Remove(b.Name())
		f, err := NewMemoryFile(b, MemoryFileOpts{SharedBaseFile: base, SharedBaseBytes: baseLen})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	rd := func(f *MemoryFile, fr memmap.FileRange, n int) []byte {
		bs, err := f.MapInternal(fr, hostarch.Read)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), bs.Head().ToSlice()[:n]...)
	}

	f1 := mk()
	defer f1.Destroy()
	fr1, err := f1.Allocate(uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	if fr1.Start >= baseLen {
		t.Fatalf("allocation landed outside base range: %v", fr1)
	}
	if got := rd(f1, fr1, 64); !bytes.Equal(got, pat[fr1.Start:fr1.Start+64]) {
		t.Fatalf("base-backed read mismatch at off %d: got %x want %x", fr1.Start, got, pat[fr1.Start:fr1.Start+64])
	}

	f2 := mk()
	defer f2.Destroy()
	fr2, err := f2.Allocate(uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	if got := rd(f2, fr2, 64); !bytes.Equal(got, pat[fr2.Start:fr2.Start+64]) {
		t.Fatalf("second MemoryFile base read mismatch")
	}

	// Copy-on-write: write through f1; the base file and f2 stay unchanged, f1 sees it.
	bs, err := f1.MapInternal(fr1, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	want := ^pat[fr1.Start]
	bs.Head().ToSlice()[0] = want
	chk := make([]byte, 1)
	if _, err := base.ReadAt(chk, int64(fr1.Start)); err != nil {
		t.Fatal(err)
	}
	if chk[0] != pat[fr1.Start] {
		t.Fatalf("base FILE mutated by a private write: %x", chk[0])
	}
	if got := rd(f2, fr2, 1); got[0] != pat[fr2.Start] {
		t.Fatalf("f2 observed f1 private write (no isolation)")
	}
	if got := rd(f1, fr1, 1); got[0] != want {
		t.Fatalf("f1 did not observe its own write: %x", got[0])
	}
}

func TestCasimirMapInternalPrefetchesMissingPage(t *testing.T) {
	backing, err := os.CreateTemp("", "casimir-prefetch-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(backing.Name())
	mf, err := NewMemoryFile(backing, MemoryFileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Destroy()
	fr, err := mf.Allocate(uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	seq, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatal(err)
	}
	page := seq.Head().ToSlice()
	resident := []byte{0}
	if err := mincore(page, resident); err != nil {
		t.Fatal(err)
	}
	if resident[0]&1 != 0 {
		t.Fatal("uncommitted page unexpectedly resident before Casimir prefetch")
	}
	mf.casimirFaults.Store(1)
	if _, err := mf.MapInternal(fr, hostarch.Read); err != nil {
		t.Fatal(err)
	}
	if err := mincore(page, resident); err != nil {
		t.Fatal(err)
	}
	if resident[0]&1 == 0 {
		t.Fatal("Casimir MapInternal did not prefetch missing page")
	}
}

func TestExportLinearBaseAndShare(t *testing.T) {
	mkMF := func(opts MemoryFileOpts) *MemoryFile {
		b, err := os.CreateTemp("", "llifs-mf-*")
		if err != nil {
			t.Fatal(err)
		}
		os.Remove(b.Name())
		f, err := NewMemoryFile(b, opts)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	src := mkMF(MemoryFileOpts{})
	defer src.Destroy()
	fr, err := src.Allocate(uint64(hostarch.PageSize), AllocOpts{Mode: AllocateAndCommit, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	bs, err := src.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	pat := make([]byte, 256)
	for i := range pat {
		pat[i] = byte(i*7 + 3)
	}
	copy(bs.Head().ToSlice(), pat)

	out, err := os.CreateTemp("", "llifs-exported-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(out.Name())
	defer out.Close()
	exSize, err := src.ExportLinearBase(out)
	if err != nil {
		t.Fatal(err)
	}
	if exSize == 0 {
		t.Fatal("export produced empty size")
	}
	chk := make([]byte, len(pat))
	if _, err := out.ReadAt(chk, int64(fr.Start)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chk, pat) {
		t.Fatalf("exported base content mismatch at off %d", fr.Start)
	}

	// S2 -> S1: the exported file works as a shared base.
	dst := mkMF(MemoryFileOpts{SharedBaseFile: out, SharedBaseBytes: exSize})
	defer dst.Destroy()
	fr2, err := dst.Allocate(uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	bs2, err := dst.MapInternal(fr2, hostarch.Read)
	if err != nil {
		t.Fatal(err)
	}
	if got := bs2.Head().ToSlice()[:len(pat)]; !bytes.Equal(got, pat) {
		t.Fatalf("shared base from export mismatch at fr2=%v", fr2)
	}
}

// TestBasePlusDeltaRestore proves the S3 restore-apply mechanism (ledger F4):
// map a shared base, then WRITE the per-agent delta pages over it (COW), yielding
// a base+delta view with isolation -- without touching the base file or peers.
func TestBasePlusDeltaRestore(t *testing.T) {
	pg := int(hostarch.PageSize)
	mkMF := func(opts MemoryFileOpts) *MemoryFile {
		b, err := os.CreateTemp("", "llifs-mf-*")
		if err != nil {
			t.Fatal(err)
		}
		os.Remove(b.Name())
		f, err := NewMemoryFile(b, opts)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	// Base: page0=0xAA, page1=0xBB.
	src := mkMF(MemoryFileOpts{})
	defer src.Destroy()
	sfr, err := src.Allocate(uint64(2*pg), AllocOpts{Mode: AllocateAndCommit, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	ssl, err := src.MapInternal(sfr, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	sb := ssl.Head().ToSlice()
	sb[0] = 0xAA
	sb[pg] = 0xBB
	base, err := os.CreateTemp("", "llifs-base-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(base.Name())
	defer base.Close()
	exSize, err := src.ExportLinearBase(base)
	if err != nil {
		t.Fatal(err)
	}

	// Clone A: map base, then apply a delta (page1 -> 0xCC) by writing over it.
	a := mkMF(MemoryFileOpts{SharedBaseFile: base, SharedBaseBytes: exSize})
	defer a.Destroy()
	afr, err := a.Allocate(uint64(2*pg), AllocOpts{Mode: AllocateUncommitted, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	asl, err := a.MapInternal(afr, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	ab := asl.Head().ToSlice()
	if ab[0] != 0xAA || ab[pg] != 0xBB {
		t.Fatalf("clone A pre-delta should read base: %x %x", ab[0], ab[pg])
	}
	ab[pg] = 0xCC // delta apply (COW)
	if ab[0] != 0xAA || ab[pg] != 0xCC {
		t.Fatalf("clone A post-delta want AA,CC got %x,%x", ab[0], ab[pg])
	}

	// Base file must be unchanged by the delta.
	chk := make([]byte, 1)
	if _, err := base.ReadAt(chk, int64(sfr.Start)+int64(pg)); err != nil {
		t.Fatal(err)
	}
	if chk[0] != 0xBB {
		t.Fatalf("base file mutated by clone A delta: %x", chk[0])
	}

	// Clone B: same base, NO delta -> pure base (page1 still 0xBB), isolated from A.
	b := mkMF(MemoryFileOpts{SharedBaseFile: base, SharedBaseBytes: exSize})
	defer b.Destroy()
	bfr, err := b.Allocate(uint64(2*pg), AllocOpts{Mode: AllocateUncommitted, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	bsl, err := b.MapInternal(bfr, hostarch.Read)
	if err != nil {
		t.Fatal(err)
	}
	bb := bsl.Head().ToSlice()
	if bb[0] != 0xAA || bb[pg] != 0xBB {
		t.Fatalf("clone B (no delta) want AA,BB got %x,%x", bb[0], bb[pg])
	}
}

// TestBaseBackedRangesDelta validates the F5 delta computation: of N committed
// pages filled to match a base, only the pages modified AFTER export are reported
// as delta; the rest are base-backed (skippable on save, base-mapped on restore).
func TestBaseBackedRangesDelta(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	b, err := os.CreateTemp("", "llifs-mf-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(b.Name())
	src, err := NewMemoryFile(b, MemoryFileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Destroy()

	const npages = 8
	fr, err := src.Allocate(npages*pg, AllocOpts{Mode: AllocateAndCommit, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	sl, err := src.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	mem := sl.Head().ToSlice()
	for p := 0; p < npages; p++ {
		for i := 0; i < int(pg); i++ {
			mem[p*int(pg)+i] = byte(p*7 + 1) // distinct, non-zero per page
		}
	}

	base, err := os.CreateTemp("", "llifs-base-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(base.Name())
	defer base.Close()
	bsz, err := src.ExportLinearBase(base)
	if err != nil {
		t.Fatal(err)
	}

	// Modify pages 2 and 5 AFTER export: these become the delta.
	mem[2*int(pg)] ^= 0xFF
	mem[5*int(pg)+10] ^= 0xFF

	bb, err := src.BaseBackedRanges(base, bsz)
	if err != nil {
		t.Fatal(err)
	}
	var bbPages uint64
	for _, r := range bb {
		bbPages += r.Length() / pg
	}
	if bbPages != npages-2 {
		t.Fatalf("want %d base-backed pages, got %d (%v)", npages-2, bbPages, bb)
	}
	covered := func(off uint64) bool {
		for _, r := range bb {
			if off >= r.Start && off < r.End {
				return true
			}
		}
		return false
	}
	if covered(fr.Start+2*pg) || covered(fr.Start+5*pg) {
		t.Fatalf("a delta page was wrongly marked base-backed: %v", bb)
	}
	if !covered(fr.Start+0*pg) || !covered(fr.Start+7*pg) {
		t.Fatalf("an unmodified base page is missing from base-backed set: %v", bb)
	}
}

// TestBaseDecommitRevertsToBase validates A4: decommitting a COW-written base-range
// page MADV_DONTNEEDs the overlay (reverting it to the shared base) rather than
// fallocate-punching f.file (which would not touch the overlay -> the written value
// would wrongly persist).
func TestBaseDecommitRevertsToBase(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	base, err := os.CreateTemp("", "llifs-base-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(base.Name())
	defer base.Close()
	page0 := make([]byte, pg)
	page1 := make([]byte, pg)
	for i := range page0 {
		page0[i] = 0xAA
		page1[i] = 0xBB
	}
	base.WriteAt(page0, 0)
	base.WriteAt(page1, int64(pg))

	b, err := os.CreateTemp("", "llifs-backing-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(b.Name())
	mf, err := NewMemoryFile(b, MemoryFileOpts{SharedBaseFile: base, SharedBaseBytes: 2 * pg, DisableMemoryAccounting: true})
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Destroy()
	fr, err := mf.Allocate(2*pg, AllocOpts{Mode: AllocateUncommitted, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	sl, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	mem := sl.Head().ToSlice()
	if mem[0] != 0xAA || mem[pg] != 0xBB {
		t.Fatalf("base overlay not in effect: %#x %#x", mem[0], mem[pg])
	}
	mem[0] = 0x11 // COW-write page0 -> private dirty
	if mem[0] != 0x11 {
		t.Fatalf("COW write not visible: %#x", mem[0])
	}

	// Decommit page0: should drop the COW copy and revert to the shared base.
	mf.Decommit(memmap.FileRange{Start: fr.Start, End: fr.Start + pg})

	sl2, err := mf.MapInternal(memmap.FileRange{Start: fr.Start, End: fr.Start + pg}, hostarch.Read)
	if err != nil {
		t.Fatal(err)
	}
	if got := sl2.Head().ToSlice()[0]; got != 0xAA {
		t.Fatalf("decommit did not revert base page to shared base: got %#x want 0xAA (fallocate-punch no-op bug?)", got)
	}
	// The base file itself must be untouched.
	chk := make([]byte, 1)
	base.ReadAt(chk, 0)
	if chk[0] != 0xAA {
		t.Fatalf("base file mutated by decommit: %#x", chk[0])
	}
}
