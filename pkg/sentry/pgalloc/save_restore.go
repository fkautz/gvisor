// Copyright 2018 The gVisor Authors.
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

package pgalloc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/goid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/ringdeque"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syncevent"
	"gvisor.dev/gvisor/pkg/timing"
)

// MarkSavable marks f as savable.
func (f *MemoryFile) MarkSavable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.savable = true
}

// IsSavable returns true if f is savable.
func (f *MemoryFile) IsSavable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.savable
}

// ResourceID returns the resource ID for f.
func (f *MemoryFile) ResourceID() checkpoint.ResourceID {
	return f.opts.ResourceID
}

// memoryFileSaved is the subset of MemoryFile that is stored in checkpoints.
//
// +stateify savable
type memoryFileSaved struct {
	unwasteSmall *unwasteSet
	unwasteHuge  *unwasteSet
	unfreeSmall  *unfreeSet
	unfreeHuge   *unfreeSet
	subreleased  map[uint64]uint64
	memAcct      *memAcctSet
	chunks       []chunkInfo

	// baseBacked are committed ranges whose contents are carried by the shared
	// base file rather than by this checkpoint's pages file. Restore MUST NOT
	// write them: they are already correct in the base, and writing them would
	// copy-on-write a private page per sandbox and defeat sharing entirely.
	//
	// This is deliberately a distinct list rather than an absence from the
	// pages file. A range simply missing from the checkpoint means "not
	// committed", and conflating that with "carried by the base" would let a
	// base range the supplied file does not actually provide resolve to a
	// zero-filled page. Absent and base-carried must stay distinguishable so
	// the shortfall can fail closed instead.
	baseBacked []memmap.FileRange
}

// SaveOpts provides options to MemoryFile.SaveTo().
type SaveOpts struct {
	// If PagesFile is not nil, then page contents will be written to PagesFile
	// rather than to w.
	PagesFile *AsyncPagesFileSave

	// If ExcludeCommittedZeroPages is true, SaveTo() will scan both committed
	// and possibly-committed pages to find zero pages, whose contents are
	// saved implicitly rather than explicitly to reduce checkpoint size. If
	// ExcludeCommittedZeroPages is false, SaveTo() will scan only
	// possibly-committed pages to find zero pages.
	//
	// Enabling ExcludeCommittedZeroPages will usually increase the time taken
	// by SaveTo() (due to the larger number of pages that must be scanned),
	// but may instead improve SaveTo() and LoadFrom() time, and checkpoint
	// size, if the application has many committed zero pages.
	ExcludeCommittedZeroPages bool

	// SharedBaseFile and SharedBaseBytes are the shared base that this
	// checkpoint is saved against, covering file offsets [0,
	// SharedBaseBytes). Committed pages whose contents the base already
	// carries are recorded in memoryFileSaved.baseBacked and omitted from the
	// checkpoint, so that LoadFrom() can leave them to the base rather than
	// copy-on-writing a private page per sandbox.
	//
	// If SharedBaseFile is nil, MemoryFileOpts.SharedBaseFile is used instead.
	// That default matters: saving a MemoryFile that is running on a shared
	// base without mentioning the base produces a checkpoint that reloads the
	// whole base range, which restores byte-correct and shares nothing. The
	// only way to observe that mistake is to measure sharing, so it defaults
	// to the answer that is right whenever a base is present.
	//
	// Passing a base explicitly is for the case the default cannot serve: a
	// checkpoint saved against a base image that is minted from this very
	// MemoryFile, and so does not exist until the save is under way.
	SharedBaseFile  *os.File
	SharedBaseBytes uint64
}

// SaveTo writes f's state to the given stream.
func (f *MemoryFile) SaveTo(ctx context.Context, w io.Writer, opts *SaveOpts) error {
	if err := f.AwaitLoadAll(); err != nil {
		return fmt.Errorf("previous async page loading failed: %w", err)
	}

	// Wait for memory release.
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.haveWaste {
		f.mu.Unlock()
		runtime.Gosched()
		f.mu.Lock()
	}

	// Ensure that there are no pending evictions.
	if len(f.evictable) != 0 {
		panic(fmt.Sprintf("evictions still pending for %d users; call StartEvictions and WaitForEvictions before SaveTo", len(f.evictable)))
	}

	// Register this MemoryFile with async page saving if a pages file has been
	// provided.
	var amfs *asyncMemoryFileSave
	if opts.PagesFile != nil {
		var sf stateio.SourceFile
		if opts.PagesFile.aw.NeedRegisterSourceFD() {
			fileSize := uint64(len(f.chunksLoad())) * chunkSize
			var err error
			sf, err = opts.PagesFile.aw.RegisterSourceFD(int32(f.file.Fd()), fileSize, f.getClientFileRangeSettings(fileSize))
			if err != nil {
				return fmt.Errorf("failed to register MemoryFile with pages file: %w", err)
			}
		}
		amfs = &asyncMemoryFileSave{
			f:  f,
			pf: opts.PagesFile,
			sf: sf,
		}
	}

	// We only want to explicitly include pages containing non-zero bytes in
	// the checkpoint, to reduce the size of the checkpoint and improve restore
	// performance. Scan pages for non-zero bytes and ensure that they are
	// marked known-committed.
	//
	// If async page saving is enabled, emit writes to the pages file during
	// scanning, which is feasible since the pages metadata file and pages file
	// are distinct. If async page saving is disabled, we can't do this since
	// pages would be written to the state file before the metadata needed to
	// determine where to load them to. (We could instead emit one memAcct
	// segment at a time, immediately before the contents of the pages it
	// represents. However, each call to state.Save() writes some overhead
	// (header and type information), which would bloat the state file and slow
	// down loading when the number of memAcct segments is large.)
	timeScanStart := gohacks.Nanotime()
	var (
		allocatedBytes          uint64
		alreadyCommittedBytes   uint64
		newCommittedBytes       uint64
		alreadyUncommittedBytes uint64
		newUncommittedBytes     uint64
	)
	asyncWritePages := func(fr memmap.FileRange) {}
	if amfs != nil {
		asyncWritePages = func(fr memmap.FileRange) {
			amount := fr.Length()
			amfs.pf.mu.Lock()
			amfs.pf.unsaved.PushBack(apsRange{
				amfs:      amfs,
				FileRange: fr,
			})
			amfs.pf.saveOff += amount
			amfs.pf.mu.Unlock()
			amfs.pf.stStatus.Notify(apsSTPending)
		}
	}

	// Resolve the shared base this checkpoint is saved against, and find the
	// ranges of it that carry data. A hole in the base is not a page of zeros:
	// it is a range the base does not carry, whose real contents are installed
	// on first touch. Comparing a guest page against a hole reads zeros and so
	// compares equal, but recording that page as base-carried would hand the
	// restored guest whatever is installed there later. Only a range the base
	// actually carries can be left to the base.
	baseFile, baseBytes := opts.SharedBaseFile, opts.SharedBaseBytes
	if baseFile == nil {
		baseFile, baseBytes = f.opts.SharedBaseFile, f.opts.SharedBaseBytes
	}
	var (
		baseData dataExtents
		baseBuf  []byte
		// baseOverlayEnd is the end of the range the base actually backs, which
		// is baseBytes rounded up to a page because that is what mmap covers.
		baseOverlayEnd uint64
		baseBacked     []memmap.FileRange
	)
	if baseFile == nil || baseBytes == 0 {
		baseFile, baseBytes = nil, 0
	} else {
		fi, err := baseFile.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat shared base file: %w", err)
		}
		if size := fi.Size(); size < 0 || baseBytes > uint64(size) {
			return fmt.Errorf("shared base range (%d bytes) exceeds the shared base file (%d bytes)", baseBytes, size)
		}
		ranges, err := fileDataRanges(baseFile, baseBytes)
		if err != nil {
			return fmt.Errorf("failed to find the data ranges of the shared base file: %w", err)
		}
		baseData = dataExtents{ranges: ranges}
		baseBuf = make([]byte, hostarch.PageSize)
		baseOverlayEnd = (baseBytes + hostarch.PageSize - 1) &^ uint64(hostarch.PageSize-1)
	}
	// recordBaseBacked accumulates the ranges the base carries. The scan visits
	// offsets in ascending order, so appending keeps baseBacked sorted, and
	// coalescing keeps a run that a segment boundary split from being recorded
	// as two ranges.
	recordBaseBacked := func(fr memmap.FileRange) {
		if n := len(baseBacked); n != 0 && baseBacked[n-1].End == fr.Start {
			baseBacked[n-1].End = fr.End
			return
		}
		baseBacked = append(baseBacked, fr)
	}
	// pageIsBaseBacked reports whether the base carries exactly the contents of
	// the page at off. A failure to read the base aborts the save through
	// baseReadErr. The page itself would be safe either way, since a page not
	// recognized as base-carried is written out; but a save that quietly
	// stopped recognizing them would produce a checkpoint that restores
	// correctly and shares nothing, and nothing downstream can see that.
	//
	// Preconditions: Successive calls must pass ascending offsets.
	var baseReadErr error
	pageIsBaseBacked := func(off uint64, pg []byte) bool {
		if !baseData.carries(memmap.FileRange{off, off + hostarch.PageSize}) {
			return false
		}
		if _, err := baseFile.ReadAt(baseBuf, int64(off)); err != nil {
			if baseReadErr == nil {
				baseReadErr = fmt.Errorf("failed to read the shared base file at offset %d: %w", off, err)
			}
			return false
		}
		return bytes.Equal(pg, baseBuf)
	}

	// Reading an uncommitted page to determine if it is zero-filled will cause
	// it to become committed. Thus, we need to decommit zero-filled pages that
	// were not previously known to be committed to avoid increasing memory
	// usage during scanning. Batch decommitment of transiently-committed pages
	// to reduce host syscalls.
	var (
		decommitWarnOnce  sync.Once
		decommitPendingFR memmap.FileRange
		decommitCount     uint64
	)
	decommitNow := func(fr memmap.FileRange) {
		decommitCount++
		if err := f.decommitFile(fr); err != nil {
			// This doesn't impact the correctness of saved memory, it just
			// means that we're incrementally more likely to OOM. Complain, but
			// don't abort saving.
			decommitWarnOnce.Do(func() {
				log.Warningf("Decommitting MemoryFile offsets %v while saving failed: %v", fr, err)
			})
		}
	}
	decommitAddPage := func(off uint64) {
		// Invariants:
		// (1) All of decommitPendingFR lies within a single huge page.
		// (2) decommitPendingFR.End is hugepage-aligned iff
		// decommitPendingFR.Length() == 0.
		end := off + hostarch.PageSize
		if decommitPendingFR.End == off {
			// Merge with the existing range. By invariants, the page {off,
			// end} must be within the same huge page as the rest of
			// decommitPendingFR.
			decommitPendingFR.End = end
		} else {
			// Decommit the existing range and start a new one.
			if decommitPendingFR.Length() != 0 {
				decommitNow(decommitPendingFR)
			}
			decommitPendingFR = memmap.FileRange{off, end}
		}
		// Maintain invariants by decommitting if we've reached the end of the
		// containing huge page.
		if hostarch.IsHugePageAligned(end) {
			decommitNow(decommitPendingFR)
			decommitPendingFR = memmap.FileRange{}
		}
	}

	// Batch updates to f.memAcct to reduce set mutation overhead.
	//
	// Invariant: If updatePendingFR.Length() != 0, all of updatePendingFR
	// corresponds to a single segment in f.memAcct.
	var (
		updatePendingFR           memmap.FileRange
		updatePendingWasCommitted bool
		updatePendingNowCommitted bool
		updatePendingNowBase      bool
	)
	updateNow := func(maseg memAcctIterator, fr memmap.FileRange, wasCommitted, nowCommitted, nowBase bool) memAcctIterator {
		amount := fr.Length()
		if amount == 0 {
			return maseg
		}
		if wasCommitted != nowCommitted {
			maseg = f.memAcct.Isolate(maseg, fr)
			ma := maseg.ValuePtr()
			if nowCommitted {
				ma.knownCommitted = true
				ma.commitSeq = 0
				f.knownCommittedBytes += amount
				if !f.opts.DisableMemoryAccounting {
					usage.MemoryAccounting.Inc(amount, ma.kind, ma.memCgID)
				}
			} else {
				ma.knownCommitted = false
				ma.commitSeq = f.commitSeq
				f.knownCommittedBytes -= amount
				if !f.opts.DisableMemoryAccounting {
					usage.MemoryAccounting.Dec(amount, ma.kind, ma.memCgID)
				}
			}
			maseg = f.memAcct.Unisolate(maseg)
		}
		if nowCommitted {
			// A range the base carries stays committed -- it is present, not
			// absent -- but the checkpoint records it rather than storing it.
			if nowBase {
				recordBaseBacked(fr)
			} else {
				asyncWritePages(fr)
			}
		}
		return maseg
	}
	// Precondition: maseg.Range().IsSupersetOf(fr).
	// Postcondition: The returned memAcctIterator.Range().IsSupersetOf(fr).
	updateAddRange := func(maseg memAcctIterator, fr memmap.FileRange, wasCommitted, nowCommitted, nowBase bool) memAcctIterator {
		if updatePendingFR.End == fr.Start && updatePendingWasCommitted == wasCommitted && updatePendingNowCommitted == nowCommitted && updatePendingNowBase == nowBase {
			updatePendingFR.End = fr.End
			return maseg
		}
		if updatePendingFR.Length() != 0 {
			maseg = updateNow(maseg, updatePendingFR, updatePendingWasCommitted, updatePendingNowCommitted, updatePendingNowBase)
			if maseg.End() == fr.Start {
				maseg = maseg.NextSegment()
			}
		}
		updatePendingFR = fr
		updatePendingWasCommitted = wasCommitted
		updatePendingNowCommitted = nowCommitted
		updatePendingNowBase = nowBase
		return maseg
	}
	updateFlush := func(maseg memAcctIterator) memAcctIterator {
		if updatePendingFR.Length() != 0 {
			maseg = updateNow(maseg, updatePendingFR, updatePendingWasCommitted, updatePendingNowCommitted, updatePendingNowBase)
		}
		updatePendingFR = memmap.FileRange{}
		return maseg
	}

	zeroPage := make([]byte, hostarch.PageSize)
	// f.mu is unlocked below, allowing concurrent calls to f.UpdateUsage() to
	// observe pages that we transiently commit (for comparisons to zero) or
	// leave committed (if opts.ExcludeCommittedZeroPages is true). Set
	// f.isSaving to prevent this.
	if f.isSaving {
		panic(fmt.Sprintf("pgalloc.MemoryFile(%p).SaveTo() called concurrently", f))
	}
	f.isSaving = true
	defer func() { f.isSaving = false }()
	// Reset f.commitSeq and memAcctInfo.commitSeq to 0 to make more segments
	// in f.memAcct mergeable. This is safe because f.updateUsageLocked() is
	// excluded by f.isSaving being set to true.
	f.commitSeq = 0
	maseg := f.memAcct.FirstSegment()
	unscannedStart := uint64(0)
	for maseg.Ok() {
		ma := maseg.ValuePtr()
		if ma.wasteOrReleasing {
			// This shouldn't be possible since we waited for memory release
			// above, and f shouldn't be mutated during saving.
			panic(fmt.Sprintf("found waste or releasing pages %v during pgalloc.MemoryFile.SaveTo()", maseg.Range()))
		}
		fr := maseg.Range()
		if fr.Start < unscannedStart {
			fr.Start = unscannedStart
		}
		unscannedStart = fr.End
		allocatedBytes += fr.Length()
		ma.commitSeq = 0
		wasCommitted := ma.knownCommitted
		// A segment inside the base range must be scanned even when zero-page
		// exclusion is off, because that is the only way to learn which of its
		// pages the base already carries.
		if !opts.ExcludeCommittedZeroPages && wasCommitted && fr.Start >= baseOverlayEnd {
			alreadyCommittedBytes += fr.Length()
			maseg = updateAddRange(maseg, fr, true /* wasCommitted */, true /* nowCommitted */, false /* nowBase */)
			maseg = updateFlush(maseg)
			if maseg.End() == unscannedStart {
				maseg = maseg.NextSegment()
			}
			continue
		}
		f.forEachChunk(fr, func(chunk *chunkInfo, chunkFR memmap.FileRange) bool {
			bs := chunk.sliceAt(chunkFR)
			for pgoff := 0; pgoff < len(bs); pgoff += hostarch.PageSize {
				pg := bs[pgoff : pgoff+hostarch.PageSize]
				off := chunkFR.Start + uint64(pgoff)
				isZeroed := bytes.Equal(pg, zeroPage)
				// Leaving a page out of the checkpoint means "not committed",
				// and a page that is not committed reads as zero -- from the
				// MemoryFile's own file. Inside the base range it reads what
				// the base carries instead, so a zeroed page can only be left
				// out when the base carries exactly those bytes, which is the
				// same condition as being base-backed. Every other page in the
				// base range has to be written, zeroed or not.
				nowBase := false
				nowCommitted := !isZeroed
				if off < baseOverlayEnd {
					// A page is eligible to be left to the base only if the
					// base range contains all of it, but the overlay covers the
					// page containing the end of a base range that is not
					// page-aligned, since mmap rounds its length up. That last
					// page reads from the base too, so it also cannot be left
					// out of the checkpoint.
					nowBase = off+hostarch.PageSize <= baseBytes && pageIsBaseBacked(off, pg)
					nowCommitted = true
				}
				if !nowCommitted {
					if !wasCommitted {
						alreadyUncommittedBytes += hostarch.PageSize
						decommitAddPage(off)
					} else {
						newUncommittedBytes += hostarch.PageSize
					}
				} else {
					if !wasCommitted {
						newCommittedBytes += hostarch.PageSize
					} else {
						alreadyCommittedBytes += hostarch.PageSize
					}
				}
				maseg = updateAddRange(maseg, memmap.FileRange{off, off + hostarch.PageSize}, wasCommitted, nowCommitted, nowBase)
			}
			// f.UpdateUsage() may be called concurrently with f.SaveTo();
			// occasionally unlock f.mu to ensure that the former can promptly
			// observe f.isSaving and return. Assume that maseg is not
			// invalidated while f.mu is unlocked, since it should still be the
			// case that nothing is concurrently trying to mutate f.
			f.mu.Unlock()
			f.mu.Lock()
			return true
		})
		// We need to flush batched updates to f.memAcct whenever potentially
		// reaching the end of a segment, in order to maintain the invariant
		// that updatePendingFR corresponds to a single segment.
		maseg = updateFlush(maseg)
		// maseg might already include offsets beyond unscannedStart if it was
		// merged with a successor segment.
		if maseg.End() == unscannedStart {
			maseg = maseg.NextSegment()
		}
	}
	if decommitPendingFR.Length() != 0 {
		decommitNow(decommitPendingFR)
		decommitPendingFR = memmap.FileRange{}
	}
	if baseReadErr != nil {
		// Fail the whole save rather than emit a checkpoint that shares less of
		// the base than it should. With async page saving some pages have
		// already been queued, but no metadata has been written, so there is no
		// checkpoint to mistake for a complete one.
		return baseReadErr
	}

	durScan := time.Duration(gohacks.Nanotime() - timeScanStart)
	log.Infof("MemoryFile(%p): save scanning took %s for %d allocated bytes: %d bytes of zero pages (%d bytes expected, decommitted in %d syscalls, + %d bytes new), %d bytes of non-zero pages (%d bytes expected + %d bytes new); ExcludeCommittedZeroPages=%v",
		f,
		durScan,
		allocatedBytes,
		alreadyUncommittedBytes+newUncommittedBytes,
		alreadyUncommittedBytes,
		decommitCount,
		newUncommittedBytes,
		alreadyCommittedBytes+newCommittedBytes,
		alreadyCommittedBytes,
		newCommittedBytes,
		opts.ExcludeCommittedZeroPages)

	// Save metadata.
	timeMetadataStart := gohacks.Nanotime()
	if _, err := state.Save(ctx, w, &memoryFileSaved{
		unwasteSmall: &f.unwasteSmall,
		unwasteHuge:  &f.unwasteHuge,
		unfreeSmall:  &f.unfreeSmall,
		unfreeHuge:   &f.unfreeHuge,
		subreleased:  f.subreleased,
		memAcct:      &f.memAcct,
		chunks:       f.chunksLoad(),
		baseBacked:   baseBacked,
	}); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}
	log.Infof("MemoryFile(%p): saved metadata in %s", f, time.Duration(gohacks.Nanotime()-timeMetadataStart))

	if amfs == nil {
		// Save committed pages, skipping the ranges the base carries. LoadFrom
		// walks the same segments in the same order and skips the same ranges;
		// page contents are positional, so the two walks agreeing is what makes
		// the stream readable at all.
		ww := wire.Writer{Writer: w}
		timePagesStart := gohacks.Nanotime()
		bytesSaved := uint64(0)
		notBaseBacked := baseBackedWalker{ranges: baseBacked}
		for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
			if !maseg.ValuePtr().knownCommitted {
				continue
			}
			if err := notBaseBacked.forEach(maseg.Range(), func(fr memmap.FileRange) error {
				// Write a header to distinguish from objects.
				if err := state.WriteHeader(&ww, fr.Length(), false); err != nil {
					return err
				}
				// Write out data.
				var ioErr error
				f.forEachMappingSlice(fr, func(s []byte) {
					if ioErr != nil {
						return
					}
					_, ioErr = w.Write(s)
				})
				return ioErr
			}); err != nil {
				return err
			}
		}
		durPages := time.Duration(gohacks.Nanotime() - timePagesStart)
		log.Infof("MemoryFile(%p): saved pages in %s (%d bytes, %.3f MB/s)", f, durPages, bytesSaved, float64(bytesSaved)*1e-6/durPages.Seconds())
	}

	return nil
}

// AsyncPagesFileSave holds async page saving state for a single pages file.
type AsyncPagesFileSave struct {
	mu apfsMutex

	// saveOff is the offset in the pages file at which the next page to be
	// inserted into unsaved will be saved. saveOff is protected by mu.
	saveOff uint64

	// unsaved tracks pages that have not been saved. unsaved is protected by mu.
	unsaved ringdeque.Deque[apsRange]

	// stStatus communicates state from MemoryFile.SaveTo() and its callers to
	// the goroutine.
	stStatus syncevent.Waiter

	// Padding before fields used mostly by the async page saver goroutine:
	_ [hostarch.CacheLineSize]byte

	// bytesSaved is the number of write-completed bytes. bytesSaved is
	// protected by statsMu.
	bytesSaved uint64

	// When async page saving is enabled, MemoryFile.SaveTo() enqueues writes
	// while scanning for zero pages, and skips writing zero pages.
	// Consequently, if MemoryFile.SaveTo() finds a large number of zero pages
	// in close proximity, unsaved may become empty, causing writing to stall
	// and observed write throughput to drop. To differentiate this case from
	// write throughput being limited by I/O limitations, separately record and
	// report throughput for when the I/O queue is full (qavail == 0).
	//
	// bytesFull is the number of write-completed bytes while the I/O queue was
	// full. timeFullStart was the value of gohacks.Nanotime() when the I/O
	// queue last became full; if it is currently not full, timeFullStart is
	// MaxInt64. durFull is the duration elapsed while the I/O queue was full,
	// not counting time elapsed since timeFullStart. These fields are
	// protected by statsMu.
	bytesFull     uint64
	timeFullStart int64
	durFull       time.Duration

	// Following fields are exclusive to the async page saver goroutine.

	doneCallback func(error) // immutable

	// aw is the pages file. aw is immutable.
	aw stateio.AsyncWriter

	// maxWriteBytes is hostarch.PageRoundDown(ar.MaxWriteBytes()), cached to
	// avoid interface method calls and recomputation. maxWriteBytes is
	// immutable.
	maxWriteBytes uint64

	// qavail is unused capacity in aw.
	qavail int

	// Pages file writes are always contiguous, even when the corresponding
	// memmap.FileRanges and mappings are not. If curOp is not nil, it is the
	// current apsOp under construction, and curOpID is its index into ops.
	curOp   *apsOp
	curOpID uint32

	// opsBusy tracks which apsOps in ops are in use (correspond to
	// inflight operations or curOp).
	opsBusy bitmap.Bitmap

	// ops stores all apsOps.
	ops []apsOp

	// If err is not nil, it is the error that has terminated async page
	// saving. Note that unlike AsyncPagesFileLoad.err(),
	// AsyncPagesFileSave.err is never returned to application syscalls and
	// hence is not constrained to being an errno.
	err error
}

// Possible events in AsyncPagesFileSave.stStatus:
const (
	apsSTPending syncevent.Set = 1 << iota
	apsSTDone
)

// asyncMemoryFileSave holds state for async page saving from a single
// MemoryFile.
type asyncMemoryFileSave struct {
	// Immutable fields:
	f  *MemoryFile
	pf *AsyncPagesFileSave
	sf stateio.SourceFile
}

type apsRange struct {
	amfs *asyncMemoryFileSave
	memmap.FileRange
}

// apsOp tracks async page save state corresponding to a single AIO write
// operation.
type apsOp struct {
	// total is the number of bytes to be written by the operation.
	total uint64

	// amfs represents the MemoryFile being saved.
	amfs *asyncMemoryFileSave

	// frs are the MemoryFile ranges being saved.
	frs []memmap.FileRange

	// iovecs contains mappings of frs.
	iovecs []unix.Iovec
}

// StartAsyncPagesFileSave constructs asynchronous saving state for the pages
// file aw. It takes ownership of aw, even if it returns a non-nil error.
func StartAsyncPagesFileSave(aw stateio.AsyncWriter, doneCallback func(error)) (*AsyncPagesFileSave, error) {
	maxWriteBytes := hostarch.PageRoundDown(aw.MaxWriteBytes())
	if maxWriteBytes <= 0 {
		aw.Close()
		return nil, fmt.Errorf("stateio.AsyncWriter.MaxWriteBytes() (%d) must be at least one page)", aw.MaxWriteBytes())
	}
	// Cap maxParallel due to the uint32 range of bitmap.Bitmap.
	maxParallel := min(aw.MaxParallel(), 1<<30)
	apfs := &AsyncPagesFileSave{
		timeFullStart: math.MaxInt64,
		doneCallback:  doneCallback,
		aw:            aw,
		maxWriteBytes: maxWriteBytes,
		qavail:        maxParallel,
		opsBusy:       bitmap.New(uint32(maxParallel)),
		ops:           make([]apsOp, maxParallel),
	}
	// Mark ops in opsBusy that don't actually exist as permanently busy.
	for i, n := maxParallel, apfs.opsBusy.Size(); i < n; i++ {
		apfs.opsBusy.Add(uint32(i))
	}
	// Pre-allocate slices in ops.
	maxRanges := aw.MaxRanges()
	for i := range apfs.ops {
		op := &apfs.ops[i]
		op.frs = make([]memmap.FileRange, 0, maxRanges)
		op.iovecs = make([]unix.Iovec, 0, maxRanges)
	}
	apfs.stStatus.Init()
	go apfs.main()
	return apfs, nil
}

// MemoryFilesDone must be called after calling SaveTo() for all MemoryFiles
// saving to apfs. MemoryFilesDone may be called multiple times; subsequent
// calls have no effect.
func (apfs *AsyncPagesFileSave) MemoryFilesDone() {
	apfs.stStatus.Notify(apsSTDone)
}

// PagesFileOffset returns the offset into the pages file of the next page to
// be written.
func (apfs *AsyncPagesFileSave) PagesFileOffset() uint64 {
	return apfs.saveOff
}

func (apfs *AsyncPagesFileSave) canEnqueue() bool {
	return apfs.qavail > 0
}

// Preconditions: apfs.canEnqueue() == true.
func (apfs *AsyncPagesFileSave) enqueueCurOp() {
	if apfs.qavail <= 0 {
		panic("queue full")
	}
	op := apfs.curOp
	if op.total == 0 {
		panic("invalid write of 0 bytes")
	}
	if op.total > apfs.maxWriteBytes {
		panic(fmt.Sprintf("write of %d bytes exceeds per-write limit of %d bytes", op.total, apfs.maxWriteBytes))
	}

	apfs.qavail--
	apfs.curOp = nil
	if len(op.frs) == 1 && len(op.iovecs) == 1 {
		// Perform a non-vectorized write to save an indirection (and possible
		// userspace-to-kernelspace copy) in the AsyncWriter implementation.
		apfs.aw.AddWrite(int(apfs.curOpID), op.amfs.sf, op.frs[0], stateio.SliceFromIovec(op.iovecs[0]))
	} else {
		apfs.aw.AddWritev(int(apfs.curOpID), op.total, op.amfs.sf, op.frs, op.iovecs)
	}
}

// Preconditions:
// - apfs.canEnqueue() == true.
// - mfr.Length() > 0.
// - mfr must be page-aligned.
func (apfs *AsyncPagesFileSave) enqueueRange(mfr apsRange) uint64 {
	for {
		if apfs.curOp == nil {
			id, err := apfs.opsBusy.FirstZero(0)
			if err != nil {
				panic(fmt.Sprintf("all ops busy with qavail=%d: %v", apfs.qavail, err))
			}
			apfs.opsBusy.Add(id)
			op := &apfs.ops[id]
			op.total = 0
			op.frs = op.frs[:0]
			op.iovecs = op.iovecs[:0]
			apfs.curOp = op
			apfs.curOpID = id
		}
		n := apfs.combine(mfr)
		if n > 0 {
			return n
		}
		// Flush the existing (conflicting) op and try again with a new one.
		apfs.enqueueCurOp()
		if !apfs.canEnqueue() {
			return 0
		}
	}
}

// combine adds as much of the given save as possible to apfs.curOp and returns
// the number of bytes added.
//
// Preconditions:
// - mfr.Length() > 0.
// - mfr must be page-aligned.
func (apfs *AsyncPagesFileSave) combine(mfr apsRange) uint64 {
	op := apfs.curOp
	if op.total != 0 {
		if op.amfs != mfr.amfs {
			// Differing MemoryFile.
			return 0
		}
		if len(op.frs) == cap(op.frs) && op.frs[len(op.frs)-1].End != mfr.Start {
			// Non-contiguous in the MemoryFile, and we're out of space for
			// FileRanges.
			return 0
		}
	}

	// Apply direct length limits.
	n := mfr.Length()
	if op.total+n >= apfs.maxWriteBytes {
		n = apfs.maxWriteBytes - op.total
	}
	if n == 0 {
		return 0
	}
	mfr.End = mfr.Start + n

	// Collect iovecs, which may further limit length.
	n = 0
	mfr.amfs.f.forEachMappingSlice(mfr.FileRange, func(bs []byte) {
		if len(op.iovecs) > 0 {
			if canMergeIovecAndSlice(op.iovecs[len(op.iovecs)-1], bs) {
				op.iovecs[len(op.iovecs)-1].Len += uint64(len(bs))
				n += uint64(len(bs))
				return
			}
			if len(op.iovecs) == cap(op.iovecs) {
				return
			}
		}
		op.iovecs = append(op.iovecs, unix.Iovec{
			Base: &bs[0],
			Len:  uint64(len(bs)),
		})
		n += uint64(len(bs))
	})
	if n == 0 {
		return 0
	}
	mfr.End = mfr.Start + n

	// With the length decided, finish updating op.
	if op.total == 0 {
		op.amfs = mfr.amfs
	}
	op.total += n
	if len(op.frs) > 0 && op.frs[len(op.frs)-1].End == mfr.Start {
		op.frs[len(op.frs)-1].End = mfr.End
	} else {
		op.frs = append(op.frs, mfr.FileRange)
	}
	return n
}

func (apfs *AsyncPagesFileSave) main() {
	defer func() {
		if apfs.err != nil {
			log.Warningf("Async page saving failed: %v", apfs.err)
		}
		if err := apfs.aw.Close(); err != nil {
			// Saving success is independent of err, so log it rather than
			// propagating it.
			log.Warningf("Async page saving: stateio.AsyncWriter.Close failed: %v", err)
		}
		if apfs.doneCallback != nil {
			apfs.doneCallback(apfs.err)
		}
	}()

	maxParallel := apfs.aw.MaxParallel()
	// Storage reused between main loop iterations:
	var completions []stateio.Completion

	// Don't start timing until we have pages to save.
	apfs.stStatus.Wait()
	timeStart := gohacks.Nanotime()
	if log.IsLogging(log.Debug) {
		log.Debugf("Async page saving started")
		progressTicker := time.NewTicker(5 * time.Second)
		progressStopC := make(chan struct{})
		defer func() { close(progressStopC) }()
		go func() {
			timeLast := timeStart
			bytesSavedLast := uint64(0)
			for {
				select {
				case <-progressStopC:
					progressTicker.Stop()
					return
				case <-progressTicker.C:
					// Take a snapshot of our progress.
					apfs.mu.Lock()
					bytesSaved := apfs.bytesSaved
					bytesFull := apfs.bytesFull
					timeFullStart := apfs.timeFullStart
					durFull := apfs.durFull
					apfs.mu.Unlock()
					now := gohacks.Nanotime()
					durTotal := time.Duration(now - timeStart)
					if timeFullStart < now {
						durFull += time.Duration(now - timeFullStart)
					}
					durDelta := time.Duration(now - timeLast)
					bytesSavedDelta := bytesSaved - bytesSavedLast
					bandwidthTotal := float64(bytesSaved) * 1e-6 / durTotal.Seconds()
					bandwidthFull := float64(bytesFull) * 1e-6 / durFull.Seconds()
					bandwidthSinceLast := float64(bytesSavedDelta) * 1e-6 / durDelta.Seconds()
					log.Infof("Async page saving in progress for %s (%d bytes, %.3f MB/s); queue full for %s (%d bytes, %.3f MB/s); since last update %s ago: %d bytes, %.3f MB/s",
						durTotal.Round(time.Millisecond),
						bytesSaved,
						bandwidthTotal,
						durFull.Round(time.Millisecond),
						bytesFull,
						bandwidthFull,
						durDelta.Round(time.Millisecond),
						bytesSavedDelta,
						bandwidthSinceLast)
					timeLast = now
					bytesSavedLast = bytesSaved
				}
			}
		}()
	}

	prevFull := false
	for {
		// Enqueue as many writes as possible.
		if !apfs.canEnqueue() {
			panic("main loop invariant failed")
		}
		apfs.mu.Lock()
		apfs.aw.Reserve(apfs.saveOff)
		for !apfs.unsaved.Empty() {
			mfr := apfs.unsaved.PeekFrontPtr()
			n := apfs.enqueueRange(*mfr)
			if n == mfr.Length() {
				apfs.unsaved.RemoveFront()
			} else if n != 0 {
				mfr.Start += n
			} else {
				break
			}
			if !apfs.canEnqueue() {
				break
			}
		}
		full := apfs.qavail == 0
		if full && !prevFull {
			apfs.timeFullStart = gohacks.Nanotime()
		} else if !full && prevFull {
			apfs.durFull += time.Duration(gohacks.Nanotime() - apfs.timeFullStart)
			apfs.timeFullStart = math.MaxInt64
		}
		prevFull = full
		apfs.mu.Unlock()
		// Don't flush pending op unless it's the last one; this differs from
		// async page loading since writers are likely to be more sensitive to
		// write size than readers are to read size, and saving is less
		// latency-sensitive that loading.
		if apfs.curOp != nil && apfs.stStatus.Pending()&apsSTDone != 0 {
			apfs.enqueueCurOp()
		}

		if apfs.qavail == maxParallel {
			// We are out of work to do.
			ev := apfs.stStatus.Wait()
			if ev&apsSTPending != 0 {
				// We may have raced with MemoryFile.SaveTo() inserting into
				// apfs.unsaved.
				apfs.stStatus.Ack(apsSTPending)
				continue
			}
			if ev&apsSTDone != 0 {
				if apfs.curOp != nil {
					// Enqueue and complete the final write before finalizing.
					continue
				}
				if err := apfs.aw.Finalize(); err != nil {
					apfs.err = fmt.Errorf("stateio.AsyncWriter.Finalize failed: %w", err)
					return
				}
				// Successfully completed all saving for all MemoryFiles.
				durTotal := time.Duration(gohacks.Nanotime() - timeStart)
				apfs.mu.Lock()
				bytesTotal := apfs.bytesSaved
				bytesFull := apfs.bytesFull
				durFull := apfs.durFull
				apfs.mu.Unlock()
				bandwidthTotal := float64(bytesTotal) * 1e-6 / durTotal.Seconds()
				bandwidthFull := float64(bytesFull) * 1e-6 / durFull.Seconds()
				log.Infof("Async page saving completed in %s (%d bytes, %.3f MB/s); queue full for %s (%d bytes, %.3f MB/s)",
					durTotal.Round(time.Millisecond),
					bytesTotal,
					bandwidthTotal,
					durFull.Round(time.Millisecond),
					bytesFull,
					bandwidthFull)
				return
			}
			panic(fmt.Sprintf("unknown events in stStatus: %#x", ev))
		}

		// Wait for any number of writes to complete.
		var err error
		completions, err = apfs.aw.Wait(completions[:0], 1 /* minCompletions */)
		if err != nil {
			apfs.err = fmt.Errorf("stateio.AsyncWriter.Wait failed: %w", err)
			return
		}

		// Process completions.
		apfs.mu.Lock()
		for _, c := range completions {
			op := &apfs.ops[c.ID]
			apfs.opsBusy.Remove(uint32(c.ID))
			apfs.qavail++
			if c.Err != nil {
				apfs.mu.Unlock()
				apfs.err = fmt.Errorf("write for MemoryFile(%p) pages %v failed: %w", op.amfs.f, op.frs, c.Err)
				return
			}
			if c.N != op.total {
				apfs.mu.Unlock()
				apfs.err = fmt.Errorf("write for MemoryFile(%p) pages %v (total %d bytes) returned %d bytes", op.amfs.f, op.frs, op.total, c.N)
				return
			}
			apfs.bytesSaved += op.total
			if full {
				apfs.bytesFull += op.total
			}
		}
		apfs.mu.Unlock()
	}
}

// LoadOpts provides options to MemoryFile.LoadFrom().
type LoadOpts struct {
	// If PagesFile is not nil, then page contents will be read from PagesFile,
	// starting at offset PagesFileOffset, rather than from r. After LoadFrom
	// returns, PagesFileOffset will be updated to the offset of the first byte
	// in PagesFile after this MemoryFile's contents.
	//
	// Reading from PagesFile may continue after LoadFrom returns. If
	// DoneCallback is not nil, it will be called when reading for this
	// MemoryFile completes. DoneCallback will be called whether or not
	// LoadFrom returns a non-nil error.
	//
	// Invariant: PagesFileOffset must be page-aligned.
	PagesFile       *AsyncPagesFileLoad
	PagesFileOffset uint64
	DoneCallback    func(error)

	// Optional timeline for the restore process.
	// If async page loading is enabled, a forked timeline will be created, so
	// ownership of this timeline remains in the hands of the caller of
	// LoadFrom.
	Timeline *timing.Timeline

	// SharedBaseFile, if non-nil, is a read-only base image in MemoryFile-offset
	// layout covering [0, SharedBaseBytes). LoadFrom overlays that range of this
	// MemoryFile MAP_PRIVATE from the base, and adopts it into the MemoryFile's
	// own options so that later chunk extensions keep the overlay.
	//
	// The restore path establishes its own chunk mappings rather than going
	// through extendChunksLocked, so the base must be applied here as well; an
	// overlay installed only at extension time would miss restore entirely,
	// which is the whole case this exists for.
	//
	// This applies to the main MemoryFile only. Private MemoryFiles are saved
	// without a base and must load normally.
	SharedBaseFile  *os.File
	SharedBaseBytes uint64
}

// LoadFrom loads MemoryFile state from the given stream.
func (f *MemoryFile) LoadFrom(ctx context.Context, r io.Reader, opts *LoadOpts) (err error) {
	mfTimeline := opts.Timeline.Fork(fmt.Sprintf("mf:%p", f)).Lease()
	defer mfTimeline.End()

	defer func() {
		if opts.DoneCallback != nil {
			opts.DoneCallback(err)
		}
	}()

	// Load metadata.
	timeMetadataStart := gohacks.Nanotime()
	var mfs memoryFileSaved
	if _, err := state.Load(ctx, r, &mfs); err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}
	// A checkpoint that carries base-backed ranges is only meaningful against
	// the base that produced it. Restoring it without one would leave those
	// ranges unwritten and unbacked, so the guest would read a zero-filled page
	// where committed memory belongs -- the absent-versus-known-zero confusion
	// this list exists to prevent. Refuse before any of the checkpoint is
	// adopted into f, so that a refused restore leaves f as it found it.
	if len(mfs.baseBacked) != 0 {
		if opts.SharedBaseFile == nil {
			return fmt.Errorf(
				"checkpoint carries %d base-backed range(s) but no shared base file was supplied",
				len(mfs.baseBacked))
		}
		prevEnd := uint64(0)
		for _, fr := range mfs.baseBacked {
			// The walk below relies on these being ordered and disjoint, and a
			// walk that silently reads the wrong offsets restores the wrong
			// bytes without failing anywhere.
			if !fr.WellFormed() || fr.Length() == 0 || fr.Start < prevEnd {
				return fmt.Errorf(
					"checkpoint base-backed ranges are not ascending and disjoint: %v follows offset %d",
					fr, prevEnd)
			}
			prevEnd = fr.End
			if fr.End > opts.SharedBaseBytes {
				return fmt.Errorf(
					"checkpoint base-backed range [%d, %d) is not provided by the supplied base (%d bytes)",
					fr.Start, fr.End, opts.SharedBaseBytes)
			}
		}
	}

	f.unwasteSmall.MoveFrom(mfs.unwasteSmall)
	f.unwasteHuge.MoveFrom(mfs.unwasteHuge)
	f.unfreeSmall.MoveFrom(mfs.unfreeSmall)
	f.unfreeHuge.MoveFrom(mfs.unfreeHuge)
	f.subreleased = mfs.subreleased
	f.memAcct.MoveFrom(mfs.memAcct)
	chunks := mfs.chunks
	f.chunks.Store(&chunks)
	mfTimeline.Reached("metadata loaded")
	log.Infof("MemoryFile(%p): loaded metadata in %s", f, time.Duration(gohacks.Nanotime()-timeMetadataStart))

	fileSize := uint64(len(chunks)) * chunkSize
	if err := f.file.Truncate(int64(fileSize)); err != nil {
		return fmt.Errorf("failed to truncate MemoryFile: %w", err)
	}
	// Obtain chunk mappings, then madvise them concurrently with loading data.
	var (
		madviseEnd  atomicbitops.Uint64
		madviseChan = make(chan struct{}, 1)
		madviseWG   sync.WaitGroup
	)
	if len(chunks) != 0 {
		m, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			0,
			uintptr(fileSize),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED,
			f.file.Fd(),
			0)
		if errno != 0 {
			return fmt.Errorf("failed to mmap MemoryFile: %w", errno)
		}
		mfTimeline.Reached("mmaped chunks")
		for i := range chunks {
			chunk := &chunks[i]
			chunk.mapping = m
			m += chunkSize
		}
		// Adopt the base into this MemoryFile's options before overlaying, so
		// that chunks extended after restore keep the same backing, and so a
		// base range longer than the base file is rejected here rather than
		// faulting the guest on SIGBUS later.
		if opts.SharedBaseFile != nil && opts.SharedBaseBytes != 0 {
			fi, err := opts.SharedBaseFile.Stat()
			if err != nil {
				return fmt.Errorf("stat shared base file: %w", err)
			}
			if size := fi.Size(); size < 0 || opts.SharedBaseBytes > uint64(size) {
				return fmt.Errorf(
					"shared base range (%d bytes) exceeds the base file (%d bytes)",
					opts.SharedBaseBytes, size)
			}
			f.opts.SharedBaseFile = opts.SharedBaseFile
			f.opts.SharedBaseBytes = opts.SharedBaseBytes
			if err := f.overlaySharedBaseLocked(chunks, 0, uint64(len(chunks))); err != nil {
				return fmt.Errorf("failed to overlay shared base on restore: %w", err)
			}
			mfTimeline.Reached("overlaid shared base")
		}
		madviseWG.Add(1)
		go func() {
			defer madviseWG.Done()
			for i := range chunks {
				chunk := &chunks[i]
				f.madviseChunkMapping(chunk.mapping, chunkSize, chunk.huge)
				madviseEnd.Add(chunkSize)
				select {
				case madviseChan <- struct{}{}:
				default:
				}
			}
		}()
	}
	defer madviseWG.Wait()

	// Register this MemoryFile with async page loading if a pages file has
	// been provided.
	var amfl *asyncMemoryFileLoad
	if opts.PagesFile != nil {
		var df stateio.DestinationFile
		if opts.PagesFile.ar.NeedRegisterDestinationFD() {
			var err error
			df, err = opts.PagesFile.ar.RegisterDestinationFD(int32(f.file.Fd()), fileSize, f.getClientFileRangeSettings(fileSize))
			if err != nil {
				return fmt.Errorf("failed to register MemoryFile with pages file: %w", err)
			}
		}
		amfl = &asyncMemoryFileLoad{
			f:            f,
			pf:           opts.PagesFile,
			df:           df,
			doneCallback: opts.DoneCallback,
			timeline:     mfTimeline.Transfer(),
		}
		amfl.pf.amflsMu.Lock()
		if err := amfl.pf.err(); err != nil {
			amfl.pf.amflsMu.Unlock()
			return err
		}
		amfl.pf.amfls.PushBack(amfl)
		amfl.pf.amflsMu.Unlock()
		f.asyncPageLoad.Store(amfl)
		opts.DoneCallback = nil
		defer func() {
			amfl.pf.amflsMu.Lock()
			defer amfl.pf.amflsMu.Unlock()
			amfl.pf.mu.Lock()
			defer amfl.pf.mu.Unlock()
			amfl.lfDone = true
			if amfl.unloaded.IsEmpty() {
				// The async page loader goroutine does this when it
				// transitions amfl.unloaded from non-empty to empty with
				// amfl.lfDone == true, but since amfl.unloaded is already
				// empty (async page loading for this MemoryFile finished
				// before we got here, possibly because the MemoryFile was
				// empty), we have to do so instead.
				amfl.minUnloaded.Store(math.MaxUint64)
				amfl.pf.amfls.Remove(amfl)
				amfl.f.asyncPageLoad.Store(nil)
				amfl.timeline.End()
				if amfl.doneCallback != nil {
					amfl.doneCallback(nil)
					amfl.doneCallback = nil
				}
			}
		}()
	}

	// Load committed pages and reconstruct memory accounting state.
	wr := wire.Reader{Reader: r}
	timePagesStart := gohacks.Nanotime()
	minUnloadedInit := false
	notBaseBacked := baseBackedWalker{ranges: mfs.baseBacked}
	for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
		if !maseg.ValuePtr().knownCommitted {
			continue
		}
		maFR := maseg.Range()
		amount := maFR.Length()
		// Wait for all chunks spanned by this segment to be madvised.
		for madviseEnd.Load() < maFR.End {
			<-madviseChan
		}
		// Skip the ranges the shared base carries: they are already correct in
		// the base, and writing them would copy-on-write a page private to this
		// sandbox and share nothing, which is the entire failure this exists to
		// prevent. SaveTo left them out of the stream in this same walk order.
		if amfl != nil {
			// Record where to read data.
			if err := notBaseBacked.forEach(maFR, func(fr memmap.FileRange) error {
				if !minUnloadedInit {
					minUnloadedInit = true
					amfl.minUnloaded.Store(fr.Start)
				}
				amfl.pf.mu.Lock()
				amfl.unloaded.InsertRange(fr, aplUnloadedInfo{
					off: opts.PagesFileOffset,
				})
				amfl.pf.mu.Unlock()
				opts.PagesFileOffset += fr.Length()
				amfl.pf.lfStatus.Notify(aplLFPending)
				return nil
			}); err != nil {
				return err
			}
		} else {
			if err := notBaseBacked.forEach(maFR, func(fr memmap.FileRange) error {
				// Verify header.
				length, object, err := state.ReadHeader(&wr)
				if err != nil {
					return fmt.Errorf("failed to read header: %w", err)
				}
				if object {
					// Not expected.
					return fmt.Errorf("unexpected object")
				}
				if length != fr.Length() {
					// Size mismatch.
					return fmt.Errorf("mismatched segment: expected %d, got %d", fr.Length(), length)
				}
				// Read data.
				var ioErr error
				f.forEachMappingSlice(fr, func(s []byte) {
					if ioErr != nil {
						return
					}
					_, ioErr = io.ReadFull(r, s)
				})
				if ioErr != nil {
					return fmt.Errorf("failed to read pages: %w", ioErr)
				}
				return nil
			}); err != nil {
				return err
			}
		}

		// Update accounting for restored pages. We need to do this here since
		// these segments are marked as "known committed", and will be skipped
		// over on accounting scans.
		f.knownCommittedBytes += amount
		if !f.opts.DisableMemoryAccounting {
			usage.MemoryAccounting.Inc(amount, maseg.ValuePtr().kind, maseg.ValuePtr().memCgID)
		}
	}
	durPages := time.Duration(gohacks.Nanotime() - timePagesStart)
	if amfl != nil {
		log.Infof("MemoryFile(%p): loaded page file offsets in %s; async loading %d bytes", f, durPages, f.knownCommittedBytes)
	} else {
		log.Infof("MemoryFile(%p): loaded pages in %s (%d bytes, %.3f MB/s)", f, durPages, f.knownCommittedBytes, float64(f.knownCommittedBytes)*1e-6/durPages.Seconds())
	}

	return nil
}

// AsyncPagesFileLoad holds async page loading state for a single pages file.
type AsyncPagesFileLoad struct {
	mu apflMutex

	// If errVal is not nil, it is an error that has terminated asynchronous
	// page loading. errVal can only be set by the async page loader goroutine,
	// and can only transition from nil to non-nil once, after which it is
	// immutable. errVal is stored with mu locked.
	errVal atomic.Value

	// priority contains possibly-unstarted ranges with at least one waiter.
	// priority is protected by mu.
	priority ringdeque.Deque[aplFileRange]

	// lfStatus communicates MemoryFile.LoadFrom() state to the async page
	// loader goroutine.
	lfStatus syncevent.Waiter

	// Padding before state used mostly by the async page loader goroutine:
	_ [hostarch.CacheLineSize]byte

	// amfls tracks MemoryFiles that are currently loading from the pages file.
	// amfls is protected by amflsMu.
	amflsMu amflsMutex
	amfls   asyncMemoryFileLoadList

	// numWaiters is the current number of waiting waiters. numWaiters is
	// protected by mu.
	numWaiters int

	// totalWaiters is the number of waiters that have ever waited for pages
	// from this pages file. totalWaiters is protected by mu.
	totalWaiters int

	// timeStartWaiters was the value of gohacks.Nanotime() when numWaiters
	// most recently transitioned from 0 to 1. If numWaiters is 0,
	// timeStartWaiters is MaxInt64. timeStartWaiters is protected by mu.
	timeStartWaiters int64

	// nsWaitedOne is the duration for which at least one waiter was waiting
	// for a load. nsWaitedTotal is the duration for which waiters were waiting
	// for loads, summed across all waiters. bytesWaited is the number of bytes
	// for which at least one waiter waited. These fields are protected by mu.
	durWaitedOne   time.Duration
	durWaitedTotal time.Duration
	bytesWaited    uint64

	// bytesLoaded is the number of bytes that have been loaded so far.
	// bytesLoaded is protected by mu.
	bytesLoaded uint64

	// Following fields are exclusive to the async page loader goroutine.

	timeline     *timing.Timeline // immutable
	doneCallback func(error)      // immutable

	// ar is the pages file. ar is immutable.
	ar stateio.AsyncReader

	// maxReadBytes is hostarch.PageRoundDown(ar.MaxReadBytes()), cached to
	// avoid interface method calls and recomputation. maxReadBytes is
	// immutable.
	maxReadBytes uint64

	// qavail is unused capacity in ar.
	qavail int

	// The async page loader combines multiple loads with contiguous pages file
	// offsets (the common case) into a single read, even if their
	// corresponding memmap.FileRanges and mappings are discontiguous. If curOp
	// is not nil, it is the current aplOp under construction, and curOpID is
	// its index into ops.
	curOp   *aplOp
	curOpID uint32

	// opsBusy tracks which aplOps in ops are in use (correspond to
	// inflight operations or curOp).
	opsBusy bitmap.Bitmap

	// ops stores all aplOps.
	ops []aplOp
}

// Possible events in AsyncPagesFileLoad.lfStatus:
const (
	aplLFPending syncevent.Set = 1 << iota
	aplLFDone
)

type aplFileRange struct {
	amfl *asyncMemoryFileLoad
	memmap.FileRange
}

func (apfl *AsyncPagesFileLoad) err() error {
	if v := apfl.errVal.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// asyncMemoryFileLoad holds async page loading state for a single MemoryFile.
type asyncMemoryFileLoad struct {
	// Immutable fields:
	f            *MemoryFile
	pf           *AsyncPagesFileLoad
	df           stateio.DestinationFile
	doneCallback func(error)
	timeline     *timing.Timeline

	// minUnloaded is the MemoryFile offset of the first unloaded byte.
	minUnloaded atomicbitops.Uint64

	// unloaded tracks pages in the MemoryFile that have not been loaded.
	// unloaded is protected by pf.mu.
	unloaded aplUnloadedSet

	// lfDone is true if MemoryFile.LoadFrom() has finished inserting into
	// unloaded. lfDone is protected by pf.mu.
	lfDone bool

	// asyncMemoryFileLoadEntry links into pf.amfls. asyncMemoryFileLoadEntry
	// is protected by pf.amflsMu.
	asyncMemoryFileLoadEntry

	// Padding before state exclusive to the async page loader goroutine:
	_ [hostarch.CacheLineSize]byte

	// minUnstarted is the lowest offset that may map to a segment in unloaded
	// for which aplUnloadedInfo.started == false.
	minUnstarted uint64
}

// aplUnloadedInfo is the value type of asyncMemoryFileLoad.unloaded.
type aplUnloadedInfo struct {
	// off is the offset into the pages file at which the represented pages
	// begin.
	off uint64

	// started is true if a read has been enqueued for these pages.
	started bool

	// waiters queues goroutines waiting for these pages to be loaded.
	waiters []*aplWaiter
}

type aplWaiter struct {
	// wakeup is used by a caller of MemoryFile.awaitLoad() to block until all
	// pages in fr are loaded. wakeup is internally synchronized. fr is
	// immutable after initialization.
	wakeup syncevent.Waiter
	fr     memmap.FileRange

	// timeStart was the value of gohacks.Nanotime() when this waiter started
	// waiting. timeStart is immutable after initialization.
	timeStart int64

	// pending is the number of unloaded bytes that this waiter is waiting for.
	// pending is protected by aplShared.mu.
	pending uint64
}

var aplWaiterPool = sync.Pool{
	New: func() any {
		var w aplWaiter
		w.wakeup.Init()
		return &w
	},
}

// aplOp tracks async page load state corresponding to a single AIO read
// operation.
type aplOp struct {
	// total is the number of bytes to be read by the operation.
	total uint64

	// end is the pages file offset at which the read ends.
	end uint64

	// amfl represents the MemoryFile being loaded.
	amfl *asyncMemoryFileLoad

	// frs are the MemoryFile ranges being loaded.
	frs []memmap.FileRange

	// iovecs contains mappings of frs.
	iovecs []unix.Iovec

	// If tempRef is true, a temporary reference is held on pages in frs that
	// should be dropped after completion.
	tempRef bool
}

func (op *aplOp) off() int64 {
	return int64(op.end - op.total)
}

// StartAsyncPagesFileLoad constructs asynchronous loading state for the pages
// file ar. It takes ownership of ar, even if it returns a non-nil error.
func StartAsyncPagesFileLoad(ar stateio.AsyncReader, doneCallback func(error), timeline *timing.Timeline) (*AsyncPagesFileLoad, error) {
	maxReadBytes := hostarch.PageRoundDown(ar.MaxReadBytes())
	if maxReadBytes <= 0 {
		ar.Close()
		return nil, fmt.Errorf("stateio.AsyncReader.MaxReadBytes() (%d) must be at least one page)", ar.MaxReadBytes())
	}
	// Cap maxParallel due to the uint32 range of bitmap.Bitmap.
	maxParallel := min(ar.MaxParallel(), 1<<30)
	apfl := &AsyncPagesFileLoad{
		timeStartWaiters: math.MaxInt64,
		timeline:         timeline.Fork("async page loading"),
		doneCallback:     doneCallback,
		ar:               ar,
		maxReadBytes:     maxReadBytes,
		qavail:           maxParallel,
		opsBusy:          bitmap.New(uint32(maxParallel)),
		ops:              make([]aplOp, maxParallel),
	}
	// Mark ops in opsBusy that don't actually exist as permanently busy.
	for i, n := maxParallel, apfl.opsBusy.Size(); i < n; i++ {
		apfl.opsBusy.Add(uint32(i))
	}
	// Pre-allocate slices in ops.
	maxRanges := ar.MaxRanges()
	for i := range apfl.ops {
		op := &apfl.ops[i]
		op.frs = make([]memmap.FileRange, 0, maxRanges)
		op.iovecs = make([]unix.Iovec, 0, maxRanges)
	}
	apfl.lfStatus.Init()
	go apfl.main()
	return apfl, nil
}

// MemoryFilesDone must be called after calling LoadFrom() for all MemoryFiles
// loading from apfl. MemoryFilesDone may be called multiple times; subsequent
// calls have no effect.
func (apfl *AsyncPagesFileLoad) MemoryFilesDone() {
	apfl.lfStatus.Notify(aplLFDone)
}

// IsAsyncLoading returns true if async page loading is in progress or has
// failed permanently.
func (f *MemoryFile) IsAsyncLoading() bool {
	return f.asyncPageLoad.Load() != nil
}

// AwaitLoadAll blocks until async page loading has completed. If async page
// loading is not in progress, AwaitLoadAll returns immediately.
func (f *MemoryFile) AwaitLoadAll() error {
	if amfl := f.asyncPageLoad.Load(); amfl != nil {
		return amfl.awaitLoad(memmap.FileRange{0, hostarch.PageRoundDown(uint64(math.MaxUint64))})
	}
	return nil
}

// awaitLoad blocks until data has been loaded for all pages in fr.
//
// Preconditions: At least one reference must be held on all unloaded pages in
// fr.
func (amfl *asyncMemoryFileLoad) awaitLoad(fr memmap.FileRange) error {
	// Lockless fast path:
	if fr.End <= amfl.minUnloaded.Load() {
		return nil
	}

	// fr might not be page-aligned; everything else involved in async page
	// loading requires page-aligned FileRanges.
	fr.Start = hostarch.PageRoundDown(fr.Start)
	fr.End = hostarch.MustPageRoundUp(fr.End)

	apfl := amfl.pf
	apfl.mu.Lock()
	if err := apfl.err(); err != nil {
		if amfl.unloaded.IsEmptyRange(fr) {
			// fr is already loaded.
			apfl.mu.Unlock()
			return nil
		}
		// A previous error means that fr will never be loaded.
		apfl.mu.Unlock()
		return err
	}
	w := aplWaiterPool.Get().(*aplWaiter)
	defer aplWaiterPool.Put(w)
	w.fr = fr
	w.pending = 0
	amfl.unloaded.MutateRange(fr, func(ulseg aplUnloadedIterator) bool {
		ul := ulseg.ValuePtr()
		ulFR := ulseg.Range()
		ullen := ulFR.Length()
		if len(ul.waiters) == 0 {
			apfl.bytesWaited += ullen
			if !ul.started {
				apfl.priority.PushBack(aplFileRange{amfl, ulFR})
			}
			if logAwaitedLoads {
				log.Infof("MemoryFile(%p): prioritize %v", amfl.f, ulFR)
			}
		}
		ul.waiters = append(ul.waiters, w)
		w.pending += ullen
		return true
	})
	pending := w.pending != 0
	if pending {
		w.timeStart = gohacks.Nanotime()
		if apfl.numWaiters == 0 {
			apfl.timeStartWaiters = w.timeStart
		}
		apfl.numWaiters++
		apfl.totalWaiters++
	}
	apfl.mu.Unlock()
	if pending {
		if logAwaitedLoads {
			log.Infof("MemoryFile(%p): awaitLoad goid %d start: %v (%d bytes)", amfl.f, goid.Get(), fr, fr.Length())
		}
		w.wakeup.WaitAndAckAll()
		if logAwaitedLoads {
			waitNS := gohacks.Nanotime() - w.timeStart
			log.Infof("MemoryFile(%p): awaitLoad goid %d waited %v: %v (%d bytes)", amfl.f, goid.Get(), time.Duration(waitNS), fr, fr.Length())
		}
	}
	return apfl.err()
}

func (apfl *AsyncPagesFileLoad) canEnqueue() bool {
	return apfl.qavail > 0
}

// Preconditions: apfl.canEnqueue() == true.
func (apfl *AsyncPagesFileLoad) enqueueCurOp() {
	if apfl.qavail <= 0 {
		panic("queue full")
	}
	op := apfl.curOp
	if op.total == 0 {
		panic("invalid read of 0 bytes")
	}
	if op.total > apfl.maxReadBytes {
		panic(fmt.Sprintf("read of %d bytes exceeds per-read limit of %d bytes", op.total, apfl.maxReadBytes))
	}

	apfl.qavail--
	apfl.curOp = nil
	if len(op.frs) == 1 && len(op.iovecs) == 1 {
		// Perform a non-vectorized read to save an indirection (and possible
		// userspace-to-kernelspace copy) in the AsyncReader implementation.
		apfl.ar.AddRead(int(apfl.curOpID), op.off(), op.amfl.df, op.frs[0], stateio.SliceFromIovec(op.iovecs[0]))
	} else {
		apfl.ar.AddReadv(int(apfl.curOpID), op.off(), op.total, op.amfl.df, op.frs, op.iovecs)
	}
	if logAwaitedLoads && !op.tempRef {
		log.Infof("MemoryFile(%p): awaited opid %d start, read %d bytes: %v", op.amfl.f, apfl.curOpID, op.total, op.frs)
	}
}

// Preconditions:
// - apfl.canEnqueue() == true.
// - fr.Length() > 0.
// - fr must be page-aligned.
func (apfl *AsyncPagesFileLoad) enqueueRange(amfl *asyncMemoryFileLoad, fr memmap.FileRange, off uint64, tempRef bool) uint64 {
	for {
		if apfl.curOp == nil {
			id, err := apfl.opsBusy.FirstZero(0)
			if err != nil {
				panic(fmt.Sprintf("all ops busy with qavail=%d: %v", apfl.qavail, err))
			}
			apfl.opsBusy.Add(id)
			op := &apfl.ops[id]
			op.total = 0
			op.frs = op.frs[:0]
			op.iovecs = op.iovecs[:0]
			apfl.curOp = op
			apfl.curOpID = id
		}
		n := apfl.combine(amfl, fr, off, tempRef)
		if n > 0 {
			return n
		}
		// Flush the existing (conflicting) op and try again with a new one.
		apfl.enqueueCurOp()
		if !apfl.canEnqueue() {
			return 0
		}
	}
}

// combine adds as much of the given load as possible to g.curOp and returns
// the number of bytes added.
//
// Preconditions:
// - fr.Length() > 0.
// - fr must be page-aligned.
func (apfl *AsyncPagesFileLoad) combine(amfl *asyncMemoryFileLoad, fr memmap.FileRange, off uint64, tempRef bool) uint64 {
	op := apfl.curOp
	if op.total != 0 {
		if op.end != off {
			// Non-contiguous in the pages file.
			return 0
		}
		if op.amfl != amfl {
			// Differing MemoryFile.
			return 0
		}
		if len(op.frs) == cap(op.frs) && op.frs[len(op.frs)-1].End != fr.Start {
			// Non-contiguous in the MemoryFile, and we're out of space for
			// FileRanges.
			return 0
		}
		if op.tempRef != tempRef {
			// Incompatible reference-counting semantics. We could handle this
			// by making tempRef per-FileRange, but it's very unlikely that an
			// awaited load (tempRef=false) will happen to be followed by an
			// unawaited load (tempRef=true) at the correct offset.
			return 0
		}
	}

	// Apply direct length limits.
	n := fr.Length()
	if op.total+n >= apfl.maxReadBytes {
		n = apfl.maxReadBytes - op.total
	}
	if n == 0 {
		return 0
	}
	fr.End = fr.Start + n

	// Collect iovecs, which may further limit length.
	n = 0
	amfl.f.forEachMappingSlice(fr, func(bs []byte) {
		if len(op.iovecs) > 0 {
			if canMergeIovecAndSlice(op.iovecs[len(op.iovecs)-1], bs) {
				op.iovecs[len(op.iovecs)-1].Len += uint64(len(bs))
				n += uint64(len(bs))
				return
			}
			if len(op.iovecs) == cap(op.iovecs) {
				return
			}
		}
		op.iovecs = append(op.iovecs, unix.Iovec{
			Base: &bs[0],
			Len:  uint64(len(bs)),
		})
		n += uint64(len(bs))
	})
	if n == 0 {
		return 0
	}
	fr.End = fr.Start + n

	// With the length decided, finish updating op.
	if op.total == 0 {
		op.end = off
		op.amfl = amfl
	}
	op.end += n
	op.total += n
	op.tempRef = tempRef
	if len(op.frs) > 0 && op.frs[len(op.frs)-1].End == fr.Start {
		op.frs[len(op.frs)-1].End = fr.End
	} else {
		op.frs = append(op.frs, fr)
	}
	return n
}

func (apfl *AsyncPagesFileLoad) main() {
	defer func() {
		// Close ar first since this synchronously stops inflight I/O.
		if err := apfl.ar.Close(); err != nil {
			// Completed reads are complete irrespective of err, so log err
			// rather than propagating it.
			log.Warningf("Async page loading: stateio.AsyncReader.Close failed: %v", err)
		}
		apfl.timeline.End()
		// Wake up any remaining waiters so that they can observe apfl.err().
		// Leave all segments in asyncMemoryFileLoad.unloaded so that new
		// callers of awaitLoad() will still observe the correct (permanently
		// unloaded) segments.
		apfl.amflsMu.Lock()
		apfl.mu.Lock()
		for amfl := apfl.amfls.Front(); amfl != nil; amfl = amfl.Next() {
			for ulseg := amfl.unloaded.FirstSegment(); ulseg.Ok(); ulseg = ulseg.NextSegment() {
				ul := ulseg.ValuePtr()
				ullen := ulseg.Range().Length()
				for _, w := range ul.waiters {
					w.pending -= ullen
					if w.pending == 0 {
						w.wakeup.Notify(1)
					}
				}
				ul.started = false
				ul.waiters = nil
			}
			if amfl.doneCallback != nil {
				amfl.doneCallback(apfl.err())
				amfl.doneCallback = nil
			}
		}
		apfl.mu.Unlock()
		apfl.amflsMu.Unlock()
		if apfl.doneCallback != nil {
			apfl.doneCallback(apfl.err())
		}
	}()

	maxParallel := apfl.ar.MaxParallel()
	// Storage reused between main loop iterations:
	var completions []stateio.Completion
	var wakeups []*aplWaiter
	var decRefs []aplFileRange

	dropDelayedDecRefs := func() {
		if len(decRefs) != 0 {
			for _, fr := range decRefs {
				fr.amfl.f.DecRef(fr.FileRange)
			}
			decRefs = decRefs[:0]
		}
	}
	defer dropDelayedDecRefs()

	// Don't start timing until we have pages to load.
	apfl.lfStatus.Wait()
	timeStart := gohacks.Nanotime()
	apfl.timeline.Reached("async page loading started")
	if log.IsLogging(log.Debug) {
		log.Debugf("Async page loading started")
		progressTicker := time.NewTicker(5 * time.Second)
		progressStopC := make(chan struct{})
		defer func() { close(progressStopC) }()
		go func() {
			timeLast := timeStart
			bytesLoadedLast := uint64(0)
			for {
				select {
				case <-progressStopC:
					progressTicker.Stop()
					return
				case <-progressTicker.C:
					// Take a snapshot of our progress.
					apfl.mu.Lock()
					totalWaiters := apfl.totalWaiters
					timeStartWaiters := apfl.timeStartWaiters
					durWaitedOne := apfl.durWaitedOne
					durWaitedTotal := apfl.durWaitedTotal
					bytesWaited := apfl.bytesWaited
					bytesLoaded := apfl.bytesLoaded
					apfl.mu.Unlock()
					now := gohacks.Nanotime()
					durTotal := time.Duration(now - timeStart)
					// apfl can have at least one waiter for a very long time
					// due to new waiters enqueueing before old ones are
					// served; avoid apparent jumps in durWaitedOne.
					if timeStartWaiters < now {
						durWaitedOne += time.Duration(now - timeStartWaiters)
					}
					durDelta := time.Duration(now - timeLast)
					bytesLoadedDelta := bytesLoaded - bytesLoadedLast
					bandwidthSinceLast := float64(bytesLoadedDelta) * 1e-6 / durDelta.Seconds()
					apfl.timeline.Reached(fmt.Sprintf("%.3f MB/s", bandwidthSinceLast))
					log.Infof("Async page loading in progress for %s (%d bytes, %.3f MB/s); since last update %s ago: %d bytes, %.3f MB/s; %d waiters waited %v~%v for %d bytes", durTotal.Round(time.Millisecond), bytesLoaded, float64(bytesLoaded)*1e-6/durTotal.Seconds(), durDelta.Round(time.Millisecond), bytesLoadedDelta, bandwidthSinceLast, totalWaiters, durWaitedOne.Round(time.Millisecond), durWaitedTotal.Round(time.Millisecond), bytesWaited)
					timeLast = now
					bytesLoadedLast = bytesLoaded
				}
			}
		}()
	}

	for {
		// Enqueue as many reads as possible.
		if !apfl.canEnqueue() {
			panic("main loop invariant failed")
		}
		// Prioritize reading pages with waiters.
		apfl.mu.Lock()
		for apfl.canEnqueue() && !apfl.priority.Empty() {
			fr := apfl.priority.PopFront()
			// All pages in apfl.priority have non-zero waiters and were split
			// around fr by fr.amfl.awaitLoad(), and fr.amfl.unloaded never
			// merges segments with waiters. Thus, we don't need to split
			// around fr again, and fr.Intersect(ulseg.Range()) ==
			// ulseg.Range().
			ulseg := fr.amfl.unloaded.LowerBoundSegment(fr.Start)
			for ulseg.Ok() && ulseg.Start() < fr.End {
				ul := ulseg.ValuePtr()
				ulFR := ulseg.Range()
				if ul.started {
					fr.Start = ulFR.End
					ulseg = ulseg.NextSegment()
					continue
				}
				// Awaited pages are guaranteed to have a reference held (by
				// fr.amfl.awaitLoad() precondition), so they can't become
				// waste (which would allow them to be racily released or
				// recycled).
				n := apfl.enqueueRange(fr.amfl, ulFR, ul.off, false /* tempRef */)
				if n == 0 {
					// Try again in the next iteration of the main loop, when
					// we have space in the queue again.
					apfl.priority.PushFront(fr)
					break
				}
				ulFR.End = ulFR.Start + n
				ulseg = fr.amfl.unloaded.SplitAfter(ulseg, ulFR.End)
				ulseg.ValuePtr().started = true
				fr.Start = ulFR.End
				if fr.Length() > 0 {
					// Cycle the rest of fr to the end of apl.priority. This
					// prevents large awaited reads from starving other
					// waiters.
					apfl.priority.PushBack(fr)
					break
				}
				ulseg = ulseg.NextSegment()
			}
		}
		apfl.mu.Unlock()
		// Fill remaining queue with reads for pages with no waiters.
		if apfl.canEnqueue() {
			apfl.amflsMu.Lock()
			// Unawaited loads from earlier MemoryFiles are prioritized over
			// unawaited loads from later MemoryFiles. Callers of
			// MemoryFile.LoadFrom() (in //pkg/sentry/kernel) always load the
			// MemoryFile containing application memory before other
			// MemoryFiles (which most often store disk state); thus, this
			// property ensures that application memory is prioritized over
			// disk state. This is reasonable since memory latency is
			// significantly lower than disk latency, so applications are
			// likely to be more sensitive to elevated memory latency due to
			// awaited loads vs. elevated disk latency.
		amflsLoop:
			for amfl := apfl.amfls.Front(); amfl != nil; amfl = amfl.Next() {
				amfl.f.mu.Lock()
				apfl.mu.Lock()
				ulseg := amfl.unloaded.LowerBoundSegment(amfl.minUnstarted)
				for ulseg.Ok() {
					ul := ulseg.ValuePtr()
					ulFR := ulseg.Range()
					if ul.started {
						amfl.minUnstarted = ulFR.End
						ulseg = ulseg.NextSegment()
						continue
					}
					// We need to take page references during reading to
					// prevent pages from becoming waste due to concurrent
					// dropping of the last reference.
					n := apfl.enqueueRange(amfl, ulFR, ul.off, true /* tempRef */)
					if n == 0 {
						apfl.mu.Unlock()
						amfl.f.mu.Unlock()
						break amflsLoop
					}
					ulFR.End = ulFR.Start + n
					ulseg = amfl.unloaded.SplitAfter(ulseg, ulFR.End)
					ulseg.ValuePtr().started = true
					amfl.minUnstarted = ulFR.End
					amfl.f.incRefLocked(ulFR)
					if !apfl.canEnqueue() {
						apfl.mu.Unlock()
						amfl.f.mu.Unlock()
						break amflsLoop
					}
					ulseg = ulseg.NextSegment()
				}
				apfl.mu.Unlock()
				amfl.f.mu.Unlock()
			}
			apfl.amflsMu.Unlock()
		}
		// Flush pending op.
		if apfl.curOp != nil {
			apfl.enqueueCurOp()
		}

		if apfl.qavail == maxParallel {
			// We are out of work to do.
			ev := apfl.lfStatus.Wait()
			if ev&aplLFPending != 0 {
				// We may have raced with MemoryFile.LoadFrom() inserting into
				// asyncMemoryFileLoad.unloaded.
				apfl.lfStatus.Ack(aplLFPending)
				continue
			}
			if ev&aplLFDone != 0 {
				// Successfully completed all loading for all MemoryFiles.
				durTotal := time.Duration(gohacks.Nanotime() - timeStart)
				apfl.mu.Lock()
				log.Infof("Async page loading completed in %s (%d bytes, %.3f MB/s); %d waiters waited %v~%v for %d bytes", durTotal.Round(time.Millisecond), apfl.bytesLoaded, float64(apfl.bytesLoaded)*1e-6/durTotal.Seconds(), apfl.totalWaiters, apfl.durWaitedOne.Round(time.Millisecond), apfl.durWaitedTotal.Round(time.Millisecond), apfl.bytesWaited)
				apfl.mu.Unlock()
				return
			}
			panic(fmt.Sprintf("unknown events in lfStatus: %#x", ev))
		}

		// Wait for any number of reads to complete.
		var err error
		completions, err = apfl.ar.Wait(completions[:0], 1 /* minCompletions */)
		if err != nil {
			log.Warningf("Async page loading failed: stateio.AsyncReader.Wait failed: %v", err)
			apfl.mu.Lock()
			apfl.errVal.Store(linuxerr.EIO)
			apfl.mu.Unlock()
			return
		}

		// Process completions.
		apfl.amflsMu.Lock()
		apfl.mu.Lock()
		for _, c := range completions {
			op := &apfl.ops[c.ID]
			apfl.opsBusy.Remove(uint32(c.ID))
			apfl.qavail++
			if op.tempRef {
				// Delay f.DecRef(fr) until after dropping locks. This is
				// required to avoid lock recursion via dropping the last
				// reference => asyncMemoryFileLoad.cancelWasteLoad() =>
				// apfl.mu.Lock().
				for _, fr := range op.frs {
					decRefs = append(decRefs, aplFileRange{op.amfl, fr})
				}
			}
			if c.N != op.total {
				log.Warningf("Async page loading failed: read for MemoryFile(%p) pages %v (total %d bytes) returned %d bytes, error: %v", op.amfl.f, op.frs, op.total, c.N, c.Err)
				apfl.errVal.Store(linuxerr.EIO)
				apfl.mu.Unlock()
				apfl.amflsMu.Unlock()
				return
			}
			apfl.bytesLoaded += op.total
			amfl := op.amfl
			haveWaiters := false
			now := int64(0)
			for _, fr := range op.frs {
				// All pages in fr have been started and were split around fr
				// when they were started (above), and fr.amfl.unloaded never
				// merges started segments. Thus, we don't need to split around
				// fr again, and fr.Intersect(ulseg.Range()) == ulseg.Range().
				for ulseg := amfl.unloaded.FindSegment(fr.Start); ulseg.Ok() && ulseg.Start() < fr.End; ulseg = amfl.unloaded.Remove(ulseg).NextSegment() {
					ul := ulseg.ValuePtr()
					ullen := ulseg.Range().Length()
					if !ul.started {
						panic(fmt.Sprintf("MemoryFile(%p): completion of %v includes pages %v that were never started", amfl.f, fr, ulseg.Range()))
					}
					for _, w := range ul.waiters {
						haveWaiters = true
						w.pending -= ullen
						if w.pending == 0 {
							wakeups = append(wakeups, w)
							if now == 0 {
								now = gohacks.Nanotime()
							}
							// This definition of "wait time" skips the time
							// taken for w to wake up (bad), but avoids having
							// to lock apfl.mu again in apfl.awaitLoad()
							// (good).
							apfl.durWaitedTotal += time.Duration(now - w.timeStart)
							apfl.numWaiters--
							if apfl.numWaiters == 0 {
								apfl.durWaitedOne += time.Duration(now - apfl.timeStartWaiters)
								apfl.timeStartWaiters = math.MaxInt64
							}
						}
					}
				}
			}
			if logAwaitedLoads && haveWaiters {
				log.Infof("MemoryFile(%p): awaited opid %d complete, read %d bytes: %v", op.amfl.f, c.ID, op.total, op.frs)
			}
			// Keep amfl.minUnloaded up to date. We can only determine this
			// accurately if insertions into amfl.unloaded are complete.
			if amfl.lfDone {
				if amfl.unloaded.IsEmpty() {
					amfl.minUnloaded.Store(math.MaxUint64)
					apfl.amfls.Remove(amfl)
					amfl.f.asyncPageLoad.Store(nil)
					amfl.timeline.End()
					if amfl.doneCallback != nil {
						amfl.doneCallback(nil)
						amfl.doneCallback = nil
					}
				} else {
					amfl.minUnloaded.Store(amfl.unloaded.FirstSegment().Start())
				}
			}
		}
		apfl.mu.Unlock()
		apfl.amflsMu.Unlock()
		for _, w := range wakeups {
			w.wakeup.Notify(1)
		}
		wakeups = wakeups[:0]
		dropDelayedDecRefs()
	}
}

// Preconditions:
// - All pages in fr must be becoming waste pages.
// - fr must be page-aligned.
func (amfl *asyncMemoryFileLoad) cancelWasteLoad(fr memmap.FileRange) {
	// Lockless fast path:
	if fr.End <= amfl.minUnloaded.Load() {
		return
	}

	amfl.pf.mu.Lock()
	defer amfl.pf.mu.Unlock()
	amfl.unloaded.RemoveRangeWith(fr, func(ulseg aplUnloadedIterator) {
		ul := ulseg.ValuePtr()
		if ul.started {
			// This shouldn't be possible since page references are held while
			// reading (see MemoryFile.asyncPageLoadMain()).
			panic(fmt.Sprintf("pages %v becoming waste during inflight read from async loading", ulseg.Range()))
		}
		if n := len(ul.waiters); n != 0 {
			// This shouldn't be possible since the waiters should hold page
			// references.
			panic(fmt.Sprintf("pages %v becoming waste with %d async load waiters", ulseg.Range(), n))
		}
	})
}

type aplUnloadedSetFunctions struct{}

func (aplUnloadedSetFunctions) MinKey() uint64 {
	return 0
}

func (aplUnloadedSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (aplUnloadedSetFunctions) ClearValue(ul *aplUnloadedInfo) {
	ul.waiters = nil
}

func (aplUnloadedSetFunctions) Merge(fr1 memmap.FileRange, ul1 aplUnloadedInfo, fr2 memmap.FileRange, ul2 aplUnloadedInfo) (aplUnloadedInfo, bool) {
	if ul1.off+fr1.Length() != ul2.off {
		return aplUnloadedInfo{}, false
	}
	if ul1.started || ul2.started || len(ul1.waiters) != 0 || len(ul2.waiters) != 0 {
		// Merging would be counterproductive, since we expect that these
		// segments will shortly be removed (separately) based on AIO
		// completions, which would just necessitate splitting again.
		return aplUnloadedInfo{}, false
	}
	return ul1, true
}

func (aplUnloadedSetFunctions) Split(fr memmap.FileRange, ul aplUnloadedInfo, splitAt uint64) (aplUnloadedInfo, aplUnloadedInfo) {
	ul2 := aplUnloadedInfo{
		off:     ul.off + (splitAt - fr.Start),
		started: ul.started,
		// Setting cap(ul2.waiters) == len(ul2.waiters) makes ul2
		// "copy-on-append", saving an allocation if ul2 is never appended-to.
		// This is safe since existing elements in ul.waiters will never be
		// mutated.
		waiters: ul.waiters[:len(ul.waiters):len(ul.waiters)],
	}
	return ul, ul2
}

// fileDataRanges returns the ranges of file within [0, limit) that the file
// carries data for, in ascending order. The remainder is holes.
//
// This distinction is not an optimization. A hole reads as zeros, so a page
// compared against one compares equal to a page of zeros while the file carries
// nothing there at all; whatever is written into the hole afterwards is what a
// reader sees. Only a range that is data now can be left to the file later.
//
// Note that this moves file's offset, since SEEK_DATA and SEEK_HOLE are how the
// question is asked.
func fileDataRanges(file *os.File, limit uint64) ([]memmap.FileRange, error) {
	fd := int(file.Fd())
	var ranges []memmap.FileRange
	for off := uint64(0); off < limit; {
		dataStart, err := unix.Seek(fd, int64(off), unix.SEEK_DATA)
		if err == unix.ENXIO {
			// No data at or after off.
			break
		}
		if err != nil {
			return nil, fmt.Errorf("SEEK_DATA from offset %d: %w", off, err)
		}
		if uint64(dataStart) >= limit {
			break
		}
		holeStart, err := unix.Seek(fd, dataStart, unix.SEEK_HOLE)
		if err != nil {
			return nil, fmt.Errorf("SEEK_HOLE from offset %d: %w", dataStart, err)
		}
		if holeStart <= dataStart {
			return nil, fmt.Errorf("SEEK_HOLE from offset %d returned %d, which is not after it", dataStart, holeStart)
		}
		end := uint64(holeStart)
		if end > limit {
			end = limit
		}
		ranges = append(ranges, memmap.FileRange{uint64(dataStart), end})
		off = uint64(holeStart)
	}
	return ranges, nil
}

// dataExtents answers whether a file carries data for a range, for ascending
// ranges. It holds a cursor rather than searching, since both users walk the
// MemoryFile in order and the extent list can be as long as the file is
// fragmented.
type dataExtents struct {
	ranges []memmap.FileRange
	i      int
}

// carries reports whether the file carries data for all of fr.
//
// Preconditions: Successive calls must pass ascending, non-overlapping ranges.
func (d *dataExtents) carries(fr memmap.FileRange) bool {
	for d.i < len(d.ranges) && d.ranges[d.i].End <= fr.Start {
		d.i++
	}
	return d.i < len(d.ranges) && d.ranges[d.i].IsSupersetOf(fr)
}

// baseBackedWalker yields the parts of a range that the shared base does not
// carry, and which a checkpoint therefore has to store itself. SaveTo and
// LoadFrom both walk their committed segments through one of these, which is
// what makes the two agree on the layout of a page stream that carries no
// offsets of its own.
type baseBackedWalker struct {
	ranges []memmap.FileRange
	i      int
}

// forEach calls fn on each maximal sub-range of fr that is not in w.ranges, in
// ascending order, stopping at the first error.
//
// Preconditions: w.ranges is ascending and disjoint. Successive calls must pass
// ascending, non-overlapping ranges.
func (w *baseBackedWalker) forEach(fr memmap.FileRange, fn func(memmap.FileRange) error) error {
	for w.i < len(w.ranges) && w.ranges[w.i].End <= fr.Start {
		w.i++
	}
	start := fr.Start
	for j := w.i; j < len(w.ranges) && w.ranges[j].Start < fr.End && start < fr.End; j++ {
		bb := w.ranges[j]
		if bb.Start > start {
			if err := fn(memmap.FileRange{start, bb.Start}); err != nil {
				return err
			}
		}
		if bb.End > start {
			start = bb.End
		}
	}
	if start < fr.End {
		return fn(memmap.FileRange{start, fr.End})
	}
	return nil
}

func (f *MemoryFile) getClientFileRangeSettings(fileSize uint64) []stateio.ClientFileRangeSetting {
	if !f.opts.AdviseHugepage && !f.opts.AdviseNoHugepage {
		return nil
	}
	var cfrs []stateio.ClientFileRangeSetting
	f.forEachChunk(memmap.FileRange{0, fileSize}, func(chunk *chunkInfo, chunkFR memmap.FileRange) bool {
		if chunk.huge {
			if f.opts.AdviseHugepage {
				cfrs = append(cfrs, stateio.ClientFileRangeSetting{
					FileRange: chunkFR,
					Property:  stateio.PropertyHugepage,
				})
			}
		} else {
			if f.opts.AdviseNoHugepage {
				cfrs = append(cfrs, stateio.ClientFileRangeSetting{
					FileRange: chunkFR,
					Property:  stateio.PropertyNoHugepage,
				})
			}
		}
		return true
	})
	return cfrs
}
