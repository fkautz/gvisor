// Copyright 2024 The gVisor Authors.
// LLIFS GVISOR-3 S4: N-clone flatten measurement through the real SaveTo/LoadFrom
// base/delta path. N MemoryFiles restore one delta-only checkpoint over ONE shared
// base; /proc/self/smaps_rollup then shows the flatten directly: Rss counts the base
// once per mapping (the would-be no-sharing footprint) while Pss counts it once
// physically (the actual shared footprint), so Rss/Pss is the flatten ratio.
package pgalloc

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
)

func rollupKB(t *testing.T, key string) uint64 {
	t.Helper()
	f, err := os.Open("/proc/self/smaps_rollup")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		if strings.HasPrefix(ln, key+":") {
			fields := strings.Fields(ln)
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			return v // kB
		}
	}
	return 0
}

func TestNCloneFlatten(t *testing.T) {
	ctx := context.Background()
	pg := uint64(hostarch.PageSize)
	atoi := func(env string, def int) int {
		if v := os.Getenv(env); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
		return def
	}
	baseMB := atoi("FLATTEN_BASE_MB", 64)
	deltaMB := atoi("FLATTEN_DELTA_MB", 4)
	nClones := atoi("FLATTEN_N", 16)
	basePages := uint64(baseMB) * 256
	deltaPages := uint64(deltaMB) * 256

	// Build a warmed source MemoryFile and export it as the shared base.
	src := mkMemFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	fr, err := src.Allocate(basePages*pg, AllocOpts{Mode: AllocateAndCommit, Dir: BottomUp})
	if err != nil {
		t.Fatal(err)
	}
	ssl, err := src.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	smem := ssl.Head().ToSlice()
	for p := uint64(0); p < basePages; p++ {
		smem[p*pg] = byte(p%251 + 1) // non-zero so pages are real (not zero-excluded)
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
	// Apply a small delta, then save a delta-only checkpoint (sync path).
	for p := uint64(0); p < deltaPages; p++ {
		smem[p*pg] = 0xAA
	}
	var meta bytes.Buffer
	if err := src.SaveTo(ctx, &meta, &SaveOpts{ExcludeCommittedZeroPages: true, SharedBaseFile: base, SharedBaseBytes: bsz}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	src.Destroy() // free the source so it does not confound the rollup

	pssBefore := rollupKB(t, "Pss")

	// Restore N clones over the ONE shared base; touch every base page so the base
	// is resident (shared) and the delta is COW-private.
	clones := make([]*MemoryFile, 0, nClones)
	var sink byte
	for c := 0; c < nClones; c++ {
		dst := mkMemFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
		if err := dst.LoadFrom(ctx, bytes.NewReader(meta.Bytes()), &LoadOpts{SharedBaseFile: base, SharedBaseBytes: bsz}); err != nil {
			t.Fatalf("clone %d LoadFrom: %v", c, err)
		}
		dsl, err := dst.MapInternal(fr, hostarch.Read)
		if err != nil {
			t.Fatalf("clone %d MapInternal: %v", c, err)
		}
		dmem := dsl.Head().ToSlice()
		for p := uint64(0); p < basePages; p++ {
			sink += dmem[p*pg] // fault base pages resident
		}
		clones = append(clones, dst)
	}

	rss := rollupKB(t, "Rss")
	pss := rollupKB(t, "Pss")
	sharedClean := rollupKB(t, "Shared_Clean")
	privDirty := rollupKB(t, "Private_Dirty")

	mib := func(kb uint64) float64 { return float64(kb) / 1024 }
	t.Logf("flatten: base=%dMiB delta=%dMiB N=%d  (sink=%d)", baseMB, deltaMB, nClones, sink)
	t.Logf("  Rss=%.0fMiB (would-be no-sharing footprint: ~N*(base+delta))", mib(rss))
	t.Logf("  Pss=%.0fMiB (actual shared footprint: ~base + N*delta)", mib(pss))
	t.Logf("  Shared_Clean=%.0fMiB  Private_Dirty=%.0fMiB", mib(sharedClean), mib(privDirty))
	t.Logf("  Pss growth during restore = %.0fMiB", mib(pss-pssBefore))
	if pss > 0 {
		t.Logf("  FLATTEN (Rss/Pss) = %.1fx", float64(rss)/float64(pss))
	}
	expectNoShare := uint64(nClones) * (basePages + deltaPages) * pg
	t.Logf("  theoretical: no-share=%.0fMiB  shared=%.0fMiB  ideal flatten=%.1fx",
		mib(expectNoShare>>10), mib((basePages+uint64(nClones)*deltaPages)*pg>>10),
		float64(expectNoShare)/float64((basePages+uint64(nClones)*deltaPages)*pg))

	// Sanity: with N>=8 the base must be physically shared -> Pss well below Rss.
	if nClones >= 8 && pss*2 >= rss {
		t.Errorf("expected base sharing (Pss << Rss), got Rss=%dkB Pss=%dkB", rss, pss)
	}
	// Private dirty should be ~ N*delta (each clone COWs its own delta).
	wantPrivMiB := float64(nClones * deltaMB)
	if mib(privDirty) < wantPrivMiB*0.5 {
		t.Errorf("Private_Dirty=%.0fMiB too low; expected ~%.0fMiB (N*delta)", mib(privDirty), wantPrivMiB)
	}
	for _, c := range clones {
		c.Destroy()
	}
}
