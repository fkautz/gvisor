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

package kernel

import (
	"bytes"
	"container/list"
	"testing"
)

func TestExecveSha256Cache(t *testing.T) {
	cache := &execveSha256Cache{
		maxEntries: defaultMaxExecveSha256CacheEntries,
		entries:    make(map[execveSha256Key]*list.Element),
		lru:        list.New(),
	}

	key1 := execveSha256Key{mountID: 1, ino: 100, size: 1024, mtimeSec: 10, mtimeNsec: 5}
	hash1 := []byte("0123456789abcdef0123456789abcdef")

	// 1. Initial get should miss.
	if _, ok := cache.lookup(key1); ok {
		t.Fatalf("expected cache miss on key1")
	}

	// 2. Add and get should hit.
	cache.add(key1, hash1)
	got, ok := cache.lookup(key1)
	if !ok || !bytes.Equal(got, hash1) {
		t.Fatalf("expected hit with %s, got %s, ok: %v", hash1, got, ok)
	}

	// 3. Verify returned slice is a copy.
	got[0] = 'X'
	got2, _ := cache.lookup(key1)
	if bytes.Equal(got2, got) {
		t.Fatalf("cache returned mutable reference")
	}

	// 4. Different mtime should miss.
	key1Modified := execveSha256Key{mountID: 1, ino: 100, size: 1024, mtimeSec: 11, mtimeNsec: 5}
	if _, ok := cache.lookup(key1Modified); ok {
		t.Fatalf("expected cache miss on key1Modified")
	}

	// 5. Eviction test.
	for i := 0; i < defaultMaxExecveSha256CacheEntries+10; i++ {
		k := execveSha256Key{mountID: 2, ino: uint64(i), size: 100, mtimeSec: 1, mtimeNsec: 0}
		cache.add(k, []byte("dummy_hash_slice_thirty_two_bt"))
	}

	if len(cache.entries) > defaultMaxExecveSha256CacheEntries {
		t.Fatalf("cache entries exceeded max size: %d > %d", len(cache.entries), defaultMaxExecveSha256CacheEntries)
	}
	if cache.lru.Len() > defaultMaxExecveSha256CacheEntries {
		t.Fatalf("cache lru length exceeded max size: %d > %d", cache.lru.Len(), defaultMaxExecveSha256CacheEntries)
	}
	// Since key1 was added first and then 522 items were added, key1 should be evicted.
	if _, ok := cache.lookup(key1); ok {
		t.Fatalf("expected key1 to be evicted")
	}
}

func TestExecveSha256CacheConfigurable(t *testing.T) {
	orig := MaxExecveSha256CacheEntries()
	defer SetMaxExecveSha256CacheEntries(orig)

	// 1. Set to smaller size and verify capacity resizing + eviction.
	SetMaxExecveSha256CacheEntries(3)
	if got := MaxExecveSha256CacheEntries(); got != 3 {
		t.Fatalf("MaxExecveSha256CacheEntries, want: 3, got: %d", got)
	}

	for i := 0; i < 5; i++ {
		k := execveSha256Key{mountID: 3, ino: uint64(i), size: 50, mtimeSec: 1, mtimeNsec: 0}
		execveSha256CacheObj.add(k, []byte("dummy_hash_slice_thirty_two_bt"))
	}
	if len(execveSha256CacheObj.entries) > 3 || execveSha256CacheObj.lru.Len() > 3 {
		t.Fatalf("cache exceeded configured maxEntries 3: entries=%d lru=%d", len(execveSha256CacheObj.entries), execveSha256CacheObj.lru.Len())
	}

	// 2. Shrink capacity to 1 dynamically while populated, verify excess is evicted instantly.
	SetMaxExecveSha256CacheEntries(1)
	if len(execveSha256CacheObj.entries) != 1 || execveSha256CacheObj.lru.Len() != 1 {
		t.Fatalf("cache not shrunk to 1 when reconfigured: entries=%d lru=%d", len(execveSha256CacheObj.entries), execveSha256CacheObj.lru.Len())
	}

	// 3. Set to 0 (disabled), verify all elements cleared and additions skipped.
	SetMaxExecveSha256CacheEntries(0)
	if len(execveSha256CacheObj.entries) != 0 || execveSha256CacheObj.lru.Len() != 0 {
		t.Fatalf("cache not cleared on disabled SetMaxExecveSha256CacheEntries(0)")
	}

	k0 := execveSha256Key{mountID: 3, ino: 999, size: 50, mtimeSec: 1, mtimeNsec: 0}
	execveSha256CacheObj.add(k0, []byte("dummy_hash_slice_thirty_two_bt"))
	if _, ok := execveSha256CacheObj.lookup(k0); ok {
		t.Fatalf("expected cache miss when maxEntries <= 0")
	}
}
