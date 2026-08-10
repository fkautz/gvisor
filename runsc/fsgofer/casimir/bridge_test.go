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

package casimir

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeStore replays canned response frames and records the requests it saw. It
// is deliberately a separate encoder from the client's decoder: a shared codec
// could agree with itself about a wrong layout and the test would still pass.
type fakeStore struct {
	responses [][]byte
	requests  [][]byte
	index     int
	buf       bytes.Buffer
}

func (s *fakeStore) Write(p []byte) (int, error) {
	s.buf.Write(p)
	// A complete request is a 4-byte length plus that many bytes.
	for s.buf.Len() >= 4 {
		length := int(binary.BigEndian.Uint32(s.buf.Bytes()[:4]))
		if s.buf.Len() < 4+length {
			break
		}
		frame := make([]byte, length)
		copy(frame, s.buf.Bytes()[4:4+length])
		s.requests = append(s.requests, frame)
		s.buf.Next(4 + length)
	}
	return len(p), nil
}

func (s *fakeStore) Read(p []byte) (int, error) {
	if s.index >= len(s.responses) {
		return 0, errors.New("no more canned responses")
	}
	n := copy(p, s.responses[s.index])
	s.responses[s.index] = s.responses[s.index][n:]
	if len(s.responses[s.index]) == 0 {
		s.index++
	}
	return n, nil
}

func frame(payload []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

func TestClientStatParsesTheStoreReply(t *testing.T) {
	payload := []byte{statusOK}
	payload = binary.BigEndian.AppendUint64(payload, 4096)
	payload = binary.BigEndian.AppendUint32(payload, 0o100644)
	payload = binary.BigEndian.AppendUint32(payload, 7)
	payload = binary.BigEndian.AppendUint32(payload, 11)
	payload = append(payload, 1)
	payload = binary.BigEndian.AppendUint64(payload, 42)
	store := &fakeStore{responses: [][]byte{frame(payload)}}
	c := &client{conn: store}

	attr, err := c.Stat("bin/sh")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if attr.Size != 4096 || attr.Mode != 0o100644 || attr.UID != 7 || attr.GID != 11 || !attr.Regular {
		t.Fatalf("Stat() = %+v, want size 4096 mode 0100644 uid 7 gid 11 regular", attr)
	}
	if attr.Ino != 42 {
		t.Fatalf("Stat() Ino = %d, want 42", attr.Ino)
	}
	if len(store.requests) != 1 || store.requests[0][0] != opStat {
		t.Fatalf("request opcode = %v, want opStat", store.requests[0][0])
	}
}

func TestClientRefusalIsEIONotENOENT(t *testing.T) {
	// A refusal means a block failed verification or could not be fetched.
	// Reporting it as "no such file" would let a verification failure look like
	// a benign absence, and be cached as one.
	for _, spec := range []struct {
		status byte
		want   error
	}{
		{statusNotFound, unix.ENOENT},
		{statusWrongType, unix.EINVAL},
		{statusRefused, unix.EIO},
	} {
		store := &fakeStore{responses: [][]byte{frame([]byte{spec.status})}}
		c := &client{conn: store}
		if _, err := c.Stat("bin/sh"); !errors.Is(err, spec.want) {
			t.Errorf("status %d -> %v, want %v", spec.status, err, spec.want)
		}
	}
}

func TestClientReadRefusesAnOverlongPayload(t *testing.T) {
	// A server answering with more than was asked for must not be allowed to
	// write past the caller's buffer.
	payload := append([]byte{statusOK}, bytes.Repeat([]byte{0xa5}, 64)...)
	store := &fakeStore{responses: [][]byte{frame(payload)}}
	c := &client{conn: store}
	buf := make([]byte, 8)
	if _, err := c.ReadAt("big.dat", buf, 0); !errors.Is(err, unix.EIO) {
		t.Fatalf("ReadAt(overlong) error = %v, want EIO", err)
	}
}

func TestClientReadDirParsesAPageAndItsResumeIndex(t *testing.T) {
	entry := func(name string) []byte {
		out := binary.BigEndian.AppendUint16(nil, uint16(len(name)))
		out = append(out, name...)
		out = binary.BigEndian.AppendUint32(out, 0o040755)
		out = binary.BigEndian.AppendUint32(out, 0)
		out = binary.BigEndian.AppendUint32(out, 0)
		out = binary.BigEndian.AppendUint64(out, 0)
		// A distinct non-zero identifier per name: zero is what the client must
		// refuse, and equal values are what alias one file onto another.
		return binary.BigEndian.AppendUint64(out, uint64(name[0]))
	}
	payload := []byte{statusOK, 1}
	payload = binary.BigEndian.AppendUint32(payload, 2)
	payload = binary.BigEndian.AppendUint16(payload, 2)
	payload = append(payload, entry("a")...)
	payload = append(payload, entry("b")...)

	store := &fakeStore{responses: [][]byte{frame(payload)}}
	c := &client{conn: store}
	entries, next, more, err := c.ReadDir("srv", 0)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 2 || entries[0].Name != "a" || entries[1].Name != "b" {
		t.Fatalf("entries = %+v, want a and b", entries)
	}
	if next != 2 || !more {
		t.Fatalf("next = %d more = %v, want 2 true", next, more)
	}
}

func TestClientReadDirRefusesAPageWhoseCountDisagrees(t *testing.T) {
	// Trailing bytes mean the page and its count disagree. A partial parse
	// would silently truncate a directory, which is worse than an error.
	payload := []byte{statusOK, 0}
	payload = binary.BigEndian.AppendUint32(payload, 1)
	payload = binary.BigEndian.AppendUint16(payload, 0)
	payload = append(payload, 0xff, 0xff)

	store := &fakeStore{responses: [][]byte{frame(payload)}}
	c := &client{conn: store}
	if _, _, _, err := c.ReadDir("srv", 0); !errors.Is(err, unix.EIO) {
		t.Fatalf("ReadDir(trailing bytes) error = %v, want EIO", err)
	}
}

func TestClientReadLinkReturnsTheRawTarget(t *testing.T) {
	target := "../usr/bin/sh"
	payload := binary.BigEndian.AppendUint16([]byte{statusOK}, uint16(len(target)))
	payload = append(payload, target...)
	store := &fakeStore{responses: [][]byte{frame(payload)}}
	c := &client{conn: store}
	got, err := c.ReadLink("bin/sh")
	if err != nil {
		t.Fatalf("ReadLink() error = %v", err)
	}
	if got != target {
		t.Fatalf("ReadLink() = %q, want %q unresolved", got, target)
	}
}

// TestClientRefusesAZeroIdentifier proves the relay will not forward the one
// value that makes every file the same file.
//
// A store that cannot identify a file must not have that silently turned into
// "identical to everything else": the Sentry keys its inode cache on this
// number, so a zero would resurface as one file's bytes served under another
// file's name, arbitrarily far from here.
func TestClientRefusesAZeroIdentifier(t *testing.T) {
	stat := []byte{statusOK}
	stat = binary.BigEndian.AppendUint64(stat, 4096)
	stat = binary.BigEndian.AppendUint32(stat, 0o100644)
	stat = binary.BigEndian.AppendUint32(stat, 0)
	stat = binary.BigEndian.AppendUint32(stat, 0)
	stat = append(stat, 1)
	stat = binary.BigEndian.AppendUint64(stat, 0)
	c := &client{conn: &fakeStore{responses: [][]byte{frame(stat)}}}
	if _, err := c.Stat("bin/sh"); !errors.Is(err, unix.EIO) {
		t.Errorf("Stat() with a zero identifier = %v, want EIO", err)
	}

	entry := binary.BigEndian.AppendUint16(nil, 1)
	entry = append(entry, 'a')
	entry = binary.BigEndian.AppendUint32(entry, 0o100644)
	entry = binary.BigEndian.AppendUint32(entry, 0)
	entry = binary.BigEndian.AppendUint32(entry, 0)
	entry = binary.BigEndian.AppendUint64(entry, 0)
	entry = binary.BigEndian.AppendUint64(entry, 0)
	page := []byte{statusOK, 0}
	page = binary.BigEndian.AppendUint32(page, 1)
	page = binary.BigEndian.AppendUint16(page, 1)
	page = append(page, entry...)
	c = &client{conn: &fakeStore{responses: [][]byte{frame(page)}}}
	if _, _, _, err := c.ReadDir("srv", 0); !errors.Is(err, unix.EIO) {
		t.Errorf("ReadDir() with a zero identifier = %v, want EIO", err)
	}
}
