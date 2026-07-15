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
	"container/list"
	"crypto/sha256"
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const defaultMaxExecveSha256CacheEntries = 512

type execveSha256Key struct {
	mountID   uint64
	ino       uint64
	size      uint64
	mtimeSec  int64
	mtimeNsec uint32
}

type execveSha256Entry struct {
	key  execveSha256Key
	hash []byte
}

type execveSha256Cache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[execveSha256Key]*list.Element
	lru        *list.List
}

var execveSha256CacheObj = execveSha256Cache{
	maxEntries: defaultMaxExecveSha256CacheEntries,
	entries:    make(map[execveSha256Key]*list.Element),
	lru:        list.New(),
}

// Register seccheck.SessionOptionHandler in init() during early binary startup so that whenever
// seccheck.Create or seccheck.Delete runs across any trace session, it invokes this registered
// callback to adjust the kernel cache capacity (`SetMaxExecveSha256CacheEntries`). This inverted
// callback design avoids circular imports between `seccheck` and `kernel`.
func init() {
	seccheck.SessionOptionHandler = func(conf *seccheck.SessionConfig) {
		if val, ok := conf.Options["max_execve_sha256_cache_entries"]; ok {
			if cnt, ok := val.(float64); ok {
				SetMaxExecveSha256CacheEntries(int(cnt))
			} else if cnt, ok := val.(int); ok {
				SetMaxExecveSha256CacheEntries(cnt)
			}
		} else {
			SetMaxExecveSha256CacheEntries(defaultMaxExecveSha256CacheEntries)
		}
	}
}

// SetMaxExecveSha256CacheEntries sets the maximum capacity of the execve SHA-256 cache.
// Setting it to <= 0 disables the cache and evicts existing entries.
func SetMaxExecveSha256CacheEntries(maxEntries int) {
	execveSha256CacheObj.setMaxCacheEntries(maxEntries)
}

// MaxExecveSha256CacheEntries returns the current maximum capacity of the execve SHA-256 cache.
func MaxExecveSha256CacheEntries() int {
	return execveSha256CacheObj.maxCacheEntries()
}

func (c *execveSha256Cache) maxCacheEntries() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxEntries
}

func (c *execveSha256Cache) setMaxCacheEntries(maxEntries int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxEntries = maxEntries
	for c.maxEntries >= 0 && c.lru.Len() > c.maxEntries {
		back := c.lru.Back()
		if back != nil {
			c.lru.Remove(back)
			entry := back.Value.(*execveSha256Entry)
			delete(c.entries, entry.key)
		}
	}
}

func (c *execveSha256Cache) lookup(key execveSha256Key) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxEntries <= 0 {
		return nil, false
	}

	if elem, ok := c.entries[key]; ok {
		c.lru.MoveToFront(elem)
		entry := elem.Value.(*execveSha256Entry)
		return append([]byte(nil), entry.hash...), true
	}
	return nil, false
}

func (c *execveSha256Cache) add(key execveSha256Key, hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxEntries <= 0 {
		return
	}

	hashCopy := append([]byte(nil), hash...)
	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*execveSha256Entry)
		entry.hash = hashCopy
		c.lru.MoveToFront(elem)
		return
	}

	if c.lru.Len() >= c.maxEntries {
		back := c.lru.Back()
		if back != nil {
			c.lru.Remove(back)
			entry := back.Value.(*execveSha256Entry)
			delete(c.entries, entry.key)
		}
	}

	entry := &execveSha256Entry{
		key:  key,
		hash: hashCopy,
	}
	elem := c.lru.PushFront(entry)
	c.entries[key] = elem
}

// resolveBinarySha256 returns the SHA-256 hash of the given executable with caching.
func resolveBinarySha256(t *Task, executable *vfs.FileDescription) []byte {
	statOpts := vfs.StatOptions{
		Mask: linux.STATX_INO | linux.STATX_SIZE | linux.STATX_MTIME,
	}
	if stat, err := executable.Stat(t, statOpts); err == nil {
		if stat.Mask&(linux.STATX_INO|linux.STATX_SIZE|linux.STATX_MTIME) == (linux.STATX_INO | linux.STATX_SIZE | linux.STATX_MTIME) {
			mountID := uint64(0)
			if mnt := executable.Mount(); mnt != nil {
				mountID = mnt.ID
			}
			key := execveSha256Key{
				mountID:   mountID,
				ino:       stat.Ino,
				size:      stat.Size,
				mtimeSec:  stat.Mtime.Sec,
				mtimeNsec: stat.Mtime.Nsec,
			}
			if hash, ok := execveSha256CacheObj.lookup(key); ok {
				return hash
			}
			hash := computeBinarySha256(t, executable)
			if hash != nil {
				execveSha256CacheObj.add(key, hash)
			}
			return hash
		}
	}
	// If retrieving file metadata fails or incomplete attributes are returned,
	// compute and return the SHA-256 hash without caching since we cannot
	// construct a reliable cache invalidation key.
	return computeBinarySha256(t, executable)
}

func computeBinarySha256(t *Task, executable *vfs.FileDescription) []byte {
	hash := sha256.New()
	buf := make([]byte, 1024*1024) // Read 1MB at a time.
	dest := usermem.BytesIOSequence(buf)
	offset := int64(0)

	for {
		if read, err := executable.PRead(t, dest, offset, vfs.ReadOptions{}); err == nil {
			hash.Write(buf[0:read])
			offset += read

		} else if err == io.EOF {
			hash.Write(buf[0:read])
			return hash.Sum(nil)

		} else {
			log.Warningf("Failed to read executable for SHA-256 hash: %v", err)
			return nil
		}
	}
}
