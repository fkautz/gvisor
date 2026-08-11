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

//go:build linux

package pgalloc

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

// basePageSpec describes one page of a test shared base file.
//
// A hole is not a page of zeros. On the shared bases this exists for, a hole is
// a range the base does not carry yet; something else fetches and installs its
// real contents on first touch. Treating a hole as zeros is therefore how a
// saved page silently becomes whatever gets fetched later.
type basePageSpec struct {
	fill byte
	hole bool
}

func filledPage(fill byte) []byte {
	pg := make([]byte, hostarch.PageSize)
	for i := range pg {
		pg[i] = fill
	}
	return pg
}

// makeSharedBaseFile returns an unlinked sparse file laid out as specified,
// with holes where specs says so.
func makeSharedBaseFile(t *testing.T, specs []basePageSpec) *os.File {
	t.Helper()
	f, err := os.CreateTemp("", "pgalloc-shared-base-*")
	if err != nil {
		t.Fatalf("failed to create shared base file: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	if err := os.Remove(f.Name()); err != nil {
		t.Fatalf("failed to unlink shared base file: %v", err)
	}
	if err := f.Truncate(int64(len(specs)) * int64(hostarch.PageSize)); err != nil {
		t.Fatalf("failed to size shared base file: %v", err)
	}
	for i, spec := range specs {
		if spec.hole {
			continue
		}
		if _, err := f.WriteAt(filledPage(spec.fill), int64(i)*int64(hostarch.PageSize)); err != nil {
			t.Fatalf("failed to write shared base page %d: %v", i, err)
		}
	}
	for i, spec := range specs {
		if spec.hole {
			requireHoleAtPage(t, f, uint64(i))
		}
	}
	return f
}

// requireHoleAtPage fails the test unless page pgno of f is a hole. Without
// this check, a filesystem that allocates blocks for the untouched range would
// turn every hole-handling assertion below into a test of nothing.
func requireHoleAtPage(t *testing.T, f *os.File, pgno uint64) {
	t.Helper()
	off := pgno * uint64(hostarch.PageSize)
	dataOff, err := unix.Seek(int(f.Fd()), int64(off), unix.SEEK_DATA)
	if err == unix.ENXIO {
		return // No data at or after off, so off is in a hole.
	}
	if err != nil {
		t.Fatalf("SEEK_DATA on the shared base file failed: %v", err)
	}
	if uint64(dataOff) < off+uint64(hostarch.PageSize) {
		t.Fatalf("shared base page %d was expected to be a hole, but SEEK_DATA found data at %d; this filesystem does not produce sparse files, so the hole cases cannot be tested here", pgno, dataOff)
	}
}

// writeSharedBasePage overwrites page pgno of the shared base file. It stands
// in for a range being fetched and installed into the base after a checkpoint
// was taken, and for the general fact that the base is shared: a page a restore
// did not copy still tracks the file it came from.
func writeSharedBasePage(t *testing.T, f *os.File, pgno uint64, fill byte) {
	t.Helper()
	if _, err := f.WriteAt(filledPage(fill), int64(pgno)*int64(hostarch.PageSize)); err != nil {
		t.Fatalf("failed to rewrite shared base page %d: %v", pgno, err)
	}
}

func newTestMemoryFile(t *testing.T, opts MemoryFileOpts) *MemoryFile {
	t.Helper()
	backing, err := os.CreateTemp("", "pgalloc-memory-file-*")
	if err != nil {
		t.Fatalf("failed to create MemoryFile backing file: %v", err)
	}
	if err := os.Remove(backing.Name()); err != nil {
		t.Fatalf("failed to unlink MemoryFile backing file: %v", err)
	}
	f, err := NewMemoryFile(backing, opts)
	if err != nil {
		t.Fatalf("NewMemoryFile failed: %v", err)
	}
	t.Cleanup(f.Destroy)
	return f
}

// mapPages returns a mapping of fr, which must lie within one chunk.
func mapPages(t *testing.T, f *MemoryFile, fr memmap.FileRange) []byte {
	t.Helper()
	bs, err := f.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(%v) failed: %v", fr, err)
	}
	if bs.NumBlocks() != 1 {
		t.Fatalf("MapInternal(%v) returned %d blocks, want 1", fr, bs.NumBlocks())
	}
	return bs.Head().ToSlice()
}

func checkPage(t *testing.T, mem []byte, pgno uint64, want []byte, what string) {
	t.Helper()
	pageSize := uint64(hostarch.PageSize)
	got := mem[pgno*pageSize : (pgno+1)*pageSize]
	if !bytes.Equal(got, want) {
		t.Errorf("%s: page %d is %s, want %s", what, pgno, describePage(got), describePage(want))
	}
}

func describePage(pg []byte) string {
	first := pg[0]
	for _, b := range pg {
		if b != first {
			return fmt.Sprintf("mixed bytes starting %#x %#x %#x", pg[0], pg[1], pg[2])
		}
	}
	return fmt.Sprintf("filled with %#x", first)
}

// allocateOverBase allocates length bytes at the start of f, which is where the
// shared base range lives.
func allocateOverBase(t *testing.T, f *MemoryFile, length uint64) memmap.FileRange {
	t.Helper()
	fr, err := f.Allocate(length, AllocOpts{Mode: AllocateAndCommit, Dir: BottomUp})
	if err != nil {
		t.Fatalf("Allocate(%d) failed: %v", length, err)
	}
	if fr.Start != 0 || fr.Length() != length {
		t.Fatalf("Allocate(%d) returned %v, want [0, %d)", length, fr, length)
	}
	return fr
}

// saveSync saves f to a buffer using the synchronous pages path, where page
// contents follow the metadata in the same stream.
func saveSync(t *testing.T, f *MemoryFile, opts *SaveOpts) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	if err := f.SaveTo(context.Background(), &buf, opts); err != nil {
		t.Fatalf("SaveTo failed: %v", err)
	}
	return &buf
}

// TestSaveToOmitsPagesTheSharedBaseAlreadyCarries is the requirement this whole
// mechanism exists for: a restore that writes the base range back out of its
// own checkpoint copy-on-writes every one of those pages into a private copy,
// so the guest resumes byte-correct while sharing nothing. Byte equality alone
// cannot see that, so this checks what byte equality misses -- whether the
// restored range still tracks the shared file.
func TestSaveToOmitsPagesTheSharedBaseAlreadyCarries(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	const numPages = 8
	specs := make([]basePageSpec, numPages)
	for i := range specs {
		specs[i] = basePageSpec{fill: byte(i + 1)}
	}
	base := makeSharedBaseFile(t, specs)
	baseBytes := numPages * pageSize

	src := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		SharedBaseFile:          base,
		SharedBaseBytes:         baseBytes,
	})
	fr := allocateOverBase(t, src, baseBytes)
	mem := mapPages(t, src, fr)
	// Untouched pages already read what the base carries, through the overlay.
	// Dirty two of them, which the checkpoint must carry itself.
	const dirtyA, dirtyB = 3, 5
	copy(mem[dirtyA*pageSize:], filledPage(0xa1))
	copy(mem[dirtyB*pageSize:], filledPage(0xb2))

	saved := saveSync(t, src, &SaveOpts{ExcludeCommittedZeroPages: true})
	if saved.Len() >= int(baseBytes) {
		t.Errorf("checkpoint is %d bytes for %d bytes of guest memory, six pages of which the base already carries; the base range was written into the checkpoint", saved.Len(), baseBytes)
	}

	dst := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	if err := dst.LoadFrom(context.Background(), bytes.NewReader(saved.Bytes()), &LoadOpts{
		SharedBaseFile:  base,
		SharedBaseBytes: baseBytes,
	}); err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}
	dstMem := mapPages(t, dst, fr)
	for i := uint64(0); i < numPages; i++ {
		want := filledPage(byte(i + 1))
		switch i {
		case dirtyA:
			want = filledPage(0xa1)
		case dirtyB:
			want = filledPage(0xb2)
		}
		checkPage(t, dstMem, i, want, "after restore")
	}
	if t.Failed() {
		return
	}

	// A page restore did not write is still a mapping of the shared file, so
	// rewriting the file shows through. A page restore did write was
	// copy-on-written into a private copy, so it does not. This is the
	// difference between sharing the base and privately duplicating it.
	writeSharedBasePage(t, base, 1, 0xf1)
	writeSharedBasePage(t, base, dirtyA, 0xf2)
	checkPage(t, dstMem, 1, filledPage(0xf1), "after rewriting the shared base, a page the base carries")
	checkPage(t, dstMem, dirtyA, filledPage(0xa1), "after rewriting the shared base, a page this sandbox dirtied")
}

// TestSaveToKeepsZeroPagesWrittenOverNonZeroBase covers the corruption that the
// existing zero-page exclusion causes once a base is underneath. Outside the
// base range an uncommitted page reads as zero, so a zero page can be dropped
// from the checkpoint. Inside the base range an uncommitted page reads whatever
// the base carries, so dropping a zeroed page resurrects the base's contents.
func TestSaveToKeepsZeroPagesWrittenOverNonZeroBase(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	const numPages = 4
	const zeroed = 2
	specs := make([]basePageSpec, numPages)
	for i := range specs {
		specs[i] = basePageSpec{fill: byte(i + 0x10)}
	}
	base := makeSharedBaseFile(t, specs)
	baseBytes := numPages * pageSize

	src := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		SharedBaseFile:          base,
		SharedBaseBytes:         baseBytes,
	})
	fr := allocateOverBase(t, src, baseBytes)
	mem := mapPages(t, src, fr)
	clear(mem[zeroed*pageSize : (zeroed+1)*pageSize])

	saved := saveSync(t, src, &SaveOpts{ExcludeCommittedZeroPages: true})

	dst := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	if err := dst.LoadFrom(context.Background(), bytes.NewReader(saved.Bytes()), &LoadOpts{
		SharedBaseFile:  base,
		SharedBaseBytes: baseBytes,
	}); err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}
	dstMem := mapPages(t, dst, fr)
	checkPage(t, dstMem, zeroed, make([]byte, pageSize), "a page this sandbox zeroed over non-zero base content")
}

// TestSaveToNeverRecordsBaseHolesAsBaseCarried covers the other half of the same
// hazard, and the reason a byte comparison against the base is not enough on its
// own. A hole reads as zeros through both the file and the mapping, so a zeroed
// guest page over a hole compares equal to the base -- but the base does not
// carry those bytes. Whatever is fetched into the hole later becomes what the
// guest reads, which is not what it saved.
func TestSaveToNeverRecordsBaseHolesAsBaseCarried(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	const numPages = 4
	const holed = 1
	specs := make([]basePageSpec, numPages)
	for i := range specs {
		specs[i] = basePageSpec{fill: byte(i + 0x20)}
	}
	specs[holed] = basePageSpec{hole: true}
	base := makeSharedBaseFile(t, specs)
	baseBytes := numPages * pageSize

	src := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		SharedBaseFile:          base,
		SharedBaseBytes:         baseBytes,
	})
	fr := allocateOverBase(t, src, baseBytes)
	mem := mapPages(t, src, fr)
	// The hole reads as zeros, and this sandbox leaves it that way.
	checkPage(t, mem, holed, make([]byte, pageSize), "before saving, a page the base does not carry")

	saved := saveSync(t, src, &SaveOpts{ExcludeCommittedZeroPages: true})

	// The range is fetched and installed into the shared base after the
	// checkpoint was taken. The restored sandbox must still see what it saved.
	writeSharedBasePage(t, base, holed, 0xcc)

	dst := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	if err := dst.LoadFrom(context.Background(), bytes.NewReader(saved.Bytes()), &LoadOpts{
		SharedBaseFile:  base,
		SharedBaseBytes: baseBytes,
	}); err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}
	dstMem := mapPages(t, dst, fr)
	checkPage(t, dstMem, holed, make([]byte, pageSize), "a page the base did not carry when the checkpoint was taken")
}

// TestSaveRestoreInterleavesBaseCarriedAndDeltaPages is the positional check.
// Page contents are a stream whose layout both halves have to agree on; if save
// omits a range that load still expects, or the two disagree about where a range
// begins, every page after the disagreement restores with the wrong contents and
// nothing reports an error.
func TestSaveRestoreInterleavesBaseCarriedAndDeltaPages(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	const numPages = 16
	specs := make([]basePageSpec, numPages)
	for i := range specs {
		specs[i] = basePageSpec{fill: byte(i + 0x40)}
	}
	base := makeSharedBaseFile(t, specs)
	baseBytes := numPages * pageSize

	src := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		SharedBaseFile:          base,
		SharedBaseBytes:         baseBytes,
	})
	fr := allocateOverBase(t, src, baseBytes)
	mem := mapPages(t, src, fr)
	want := make([][]byte, numPages)
	for i := uint64(0); i < numPages; i++ {
		want[i] = filledPage(byte(i + 0x40))
		if i%2 == 1 {
			want[i] = filledPage(byte(i + 0x80))
			copy(mem[i*pageSize:], want[i])
		}
	}

	saved := saveSync(t, src, &SaveOpts{ExcludeCommittedZeroPages: true})

	dst := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	if err := dst.LoadFrom(context.Background(), bytes.NewReader(saved.Bytes()), &LoadOpts{
		SharedBaseFile:  base,
		SharedBaseBytes: baseBytes,
	}); err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}
	dstMem := mapPages(t, dst, fr)
	for i := uint64(0); i < numPages; i++ {
		checkPage(t, dstMem, i, want[i], "after restore")
	}
}

// TestAsyncPagesFileSaveRestoreWithSharedBase runs the same split through the
// pages-file path, which is the one a real checkpoint uses. It has its own
// offset bookkeeping, so agreeing with the synchronous path proves nothing about
// it.
func TestAsyncPagesFileSaveRestoreWithSharedBase(t *testing.T) {
	ctx := context.Background()
	pageSize := uint64(hostarch.PageSize)
	const numPages = 8
	const dirty = 6
	specs := make([]basePageSpec, numPages)
	for i := range specs {
		specs[i] = basePageSpec{fill: byte(i + 0x60)}
	}
	base := makeSharedBaseFile(t, specs)
	baseBytes := numPages * pageSize

	src := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		SharedBaseFile:          base,
		SharedBaseBytes:         baseBytes,
	})
	fr := allocateOverBase(t, src, baseBytes)
	mem := mapPages(t, src, fr)
	copy(mem[dirty*pageSize:], filledPage(0xde))

	pagesFile, err := os.CreateTemp("", "pgalloc-pages-file-*")
	if err != nil {
		t.Fatalf("failed to create pages file: %v", err)
	}
	defer os.Remove(pagesFile.Name())
	pagesFileName := pagesFile.Name()
	pagesFile.Close()

	wfd, err := unix.Open(pagesFileName, unix.O_RDWR|unix.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("failed to open pages file for writing: %v", err)
	}
	var saveWG sync.WaitGroup
	var asyncSaveErr error
	saveWG.Add(1)
	apfs, err := StartAsyncPagesFileSave(stateio.NewPagesFileFDWriterDefault(int32(wfd)), func(err error) {
		asyncSaveErr = err
		saveWG.Done()
	})
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave failed: %v", err)
	}
	var meta bytes.Buffer
	if err := src.SaveTo(ctx, &meta, &SaveOpts{PagesFile: apfs, ExcludeCommittedZeroPages: true}); err != nil {
		t.Fatalf("SaveTo failed: %v", err)
	}
	apfs.MemoryFilesDone()
	saveWG.Wait()
	if asyncSaveErr != nil {
		t.Fatalf("async page save failed: %v", asyncSaveErr)
	}
	if fi, err := os.Stat(pagesFileName); err != nil {
		t.Fatalf("failed to stat pages file: %v", err)
	} else if fi.Size() >= int64(baseBytes) {
		t.Errorf("pages file is %d bytes for %d bytes of guest memory, seven pages of which the base already carries; the base range was written into the pages file", fi.Size(), baseBytes)
	}

	rfd, err := unix.Open(pagesFileName, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open pages file for reading: %v", err)
	}
	var loadWG sync.WaitGroup
	var asyncLoadErr error
	loadWG.Add(1)
	apfl, err := StartAsyncPagesFileLoad(stateio.NewPagesFileFDReaderDefault(int32(rfd)), func(err error) {
		asyncLoadErr = err
		loadWG.Done()
	}, nil)
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad failed: %v", err)
	}
	dst := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	if err := dst.LoadFrom(ctx, bytes.NewReader(meta.Bytes()), &LoadOpts{
		PagesFile:       apfl,
		SharedBaseFile:  base,
		SharedBaseBytes: baseBytes,
	}); err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}
	apfl.MemoryFilesDone()
	if err := dst.AwaitLoadAll(); err != nil {
		t.Fatalf("AwaitLoadAll failed: %v", err)
	}
	loadWG.Wait()
	if asyncLoadErr != nil {
		t.Fatalf("async page load failed: %v", asyncLoadErr)
	}

	dstMem := mapPages(t, dst, fr)
	for i := uint64(0); i < numPages; i++ {
		want := filledPage(byte(i + 0x60))
		if i == dirty {
			want = filledPage(0xde)
		}
		checkPage(t, dstMem, i, want, "after restore")
	}
	if t.Failed() {
		return
	}
	writeSharedBasePage(t, base, 2, 0xf3)
	writeSharedBasePage(t, base, dirty, 0xf4)
	checkPage(t, dstMem, 2, filledPage(0xf3), "after rewriting the shared base, a page the base carries")
	checkPage(t, dstMem, dirty, filledPage(0xde), "after rewriting the shared base, a page this sandbox dirtied")
}

// saveWithBaseCarriedRanges returns a checkpoint that records base-carried
// ranges, for the restore-side guards below.
func saveWithBaseCarriedRanges(t *testing.T, baseBytes uint64) (*os.File, *bytes.Buffer) {
	t.Helper()
	pageSize := uint64(hostarch.PageSize)
	numPages := baseBytes / pageSize
	specs := make([]basePageSpec, numPages)
	for i := range specs {
		specs[i] = basePageSpec{fill: byte(i + 0x90)}
	}
	base := makeSharedBaseFile(t, specs)
	src := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		SharedBaseFile:          base,
		SharedBaseBytes:         baseBytes,
	})
	allocateOverBase(t, src, baseBytes)
	return base, saveSync(t, src, &SaveOpts{ExcludeCommittedZeroPages: true})
}

// TestLoadFromRejectsBaseCarriedCheckpointWithoutBase: the ranges the checkpoint
// left out are only recoverable from the base that produced them. Without one
// they are absent, not zero, and restore must say so rather than resume a guest
// whose committed memory reads as zeros.
func TestLoadFromRejectsBaseCarriedCheckpointWithoutBase(t *testing.T) {
	baseBytes := 4 * uint64(hostarch.PageSize)
	_, saved := saveWithBaseCarriedRanges(t, baseBytes)

	dst := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	err := dst.LoadFrom(context.Background(), bytes.NewReader(saved.Bytes()), &LoadOpts{})
	if err == nil {
		t.Fatalf("LoadFrom without a shared base succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "base-backed") {
		t.Errorf("LoadFrom without a shared base failed with %q, want an error naming the base-backed ranges", err)
	}
}

// TestLoadFromRejectsBaseCarriedRangePastSuppliedBase: a base too short to
// contain a range the checkpoint says it carries is the same shortfall, from the
// other direction.
func TestLoadFromRejectsBaseCarriedRangePastSuppliedBase(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	baseBytes := 4 * pageSize
	base, saved := saveWithBaseCarriedRanges(t, baseBytes)

	dst := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	err := dst.LoadFrom(context.Background(), bytes.NewReader(saved.Bytes()), &LoadOpts{
		SharedBaseFile:  base,
		SharedBaseBytes: 2 * pageSize,
	})
	if err == nil {
		t.Fatalf("LoadFrom with a short shared base succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "not provided by the supplied base") {
		t.Errorf("LoadFrom with a short shared base failed with %q, want an error naming the range the base does not provide", err)
	}
}
