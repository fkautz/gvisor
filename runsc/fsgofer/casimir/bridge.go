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

// Package casimir serves a container root from an external content-addressed
// store over a private stream socket, as a gofer extension.
//
// The store verifies every byte against a trusted identifier before returning
// it, so this package is a RELAY: it can publish only what the far side
// affirmatively handed back. A block that fails verification produces a refusal
// status and no bytes at all, which reaches the sandbox as an I/O error rather
// than as a zero page or stale content.
package casimir

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/sys/unix"
)

// Wire protocol. Frames are a big-endian u32 length followed by that many
// bytes. Requests and responses alternate strictly on one connection.
const (
	opStat     = 1
	opRead     = 2
	opSeekData = 3
	opSeekHole = 4
	opReadDir  = 5
	opReadLink = 6
)

// Response status codes. The distinctions are load-bearing: an absent path must
// not be confusable with a verification failure, and neither may be reported as
// a short read, which would reach the workload as zeros.
const (
	statusOK        = 0
	statusNotFound  = 1
	statusWrongType = 2
	statusRefused   = 3
	statusNoOffset  = 4
)

const (
	// maxReadBytes bounds one read response payload, matching the server's cap.
	maxReadBytes = 1 << 16
	// maxFrameBytes bounds any response frame. Directory pages are the largest.
	maxFrameBytes = 1 << 20
	// maxPathBytes bounds one normalized path.
	maxPathBytes = 4096
)

// Attr is the subset of file metadata the store publishes.
type Attr struct {
	Size    uint64
	Mode    uint32 // st_mode: permission bits OR'd with the file type.
	UID     uint32
	GID     uint32
	Regular bool
}

// Dirent is one directory entry as the store reports it.
type Dirent struct {
	Name string
	Mode uint32
	UID  uint32
	GID  uint32
	Size uint64
}

// client is a strictly request/response connection to the store.
//
// ONE REQUEST AT A TIME, GUARDED BY A MUTEX. The protocol has no request
// identifiers, so two concurrent callers would interleave frames and each could
// read the other's response - which for a verified-bytes relay means serving
// one file's content under another file's name.
type client struct {
	mu   sync.Mutex
	conn io.ReadWriter
}

func (c *client) roundTrip(request []byte) (byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(request)))
	if _, err := c.conn.Write(header[:]); err != nil {
		return 0, nil, fmt.Errorf("write bridge request header: %w", err)
	}
	if _, err := c.conn.Write(request); err != nil {
		return 0, nil, fmt.Errorf("write bridge request body: %w", err)
	}
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return 0, nil, fmt.Errorf("read bridge response header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxFrameBytes {
		return 0, nil, fmt.Errorf("bridge response frame length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return 0, nil, fmt.Errorf("read bridge response body: %w", err)
	}
	return payload[0], payload[1:], nil
}

// statusError maps a refusal to the errno the Sentry will surface.
//
// A REFUSAL IS EIO, NEVER ENOENT. The store refuses when a block fails
// verification or cannot be fetched; reporting that as "no such file" would let
// a verification failure look like a benign absence and be cached as one.
func statusError(status byte) error {
	switch status {
	case statusNotFound:
		return unix.ENOENT
	case statusWrongType:
		return unix.EINVAL
	case statusRefused:
		return unix.EIO
	case statusNoOffset:
		return unix.ENXIO
	default:
		return unix.EIO
	}
}

func appendPath(request []byte, path string) ([]byte, error) {
	if len(path) == 0 || len(path) > maxPathBytes {
		return nil, unix.ENAMETOOLONG
	}
	request = binary.BigEndian.AppendUint16(request, uint16(len(path)))
	return append(request, path...), nil
}

// Stat returns the store's metadata for one exact path.
func (c *client) Stat(path string) (Attr, error) {
	request, err := appendPath([]byte{opStat}, path)
	if err != nil {
		return Attr{}, err
	}
	status, payload, err := c.roundTrip(request)
	if err != nil {
		return Attr{}, err
	}
	if status != statusOK {
		return Attr{}, statusError(status)
	}
	if len(payload) < 8+4+4+4+1 {
		return Attr{}, unix.EIO
	}
	return Attr{
		Size:    binary.BigEndian.Uint64(payload[0:8]),
		Mode:    binary.BigEndian.Uint32(payload[8:12]),
		UID:     binary.BigEndian.Uint32(payload[12:16]),
		GID:     binary.BigEndian.Uint32(payload[16:20]),
		Regular: payload[20] == 1,
	}, nil
}

// ReadAt fills buf from path at off, returning the number of bytes published.
//
// A SHORT RESULT IS NOT AN ERROR AND ZERO BYTES IS NOT SUCCESS: the protocol
// cannot express an empty successful payload, so a request that yields nothing
// is a refusal rather than an EOF.
func (c *client) ReadAt(path string, buf []byte, off uint64) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	length := len(buf)
	if length > maxReadBytes {
		length = maxReadBytes
	}
	request := []byte{opRead}
	request = binary.BigEndian.AppendUint64(request, off)
	request = binary.BigEndian.AppendUint32(request, uint32(length))
	request, err := appendPath(request, path)
	if err != nil {
		return 0, err
	}
	status, payload, err := c.roundTrip(request)
	if err != nil {
		return 0, err
	}
	if status != statusOK {
		return 0, statusError(status)
	}
	if len(payload) > length {
		// More than was asked for: the relay must not write past the caller's
		// buffer, and a server that over-answers is not one to trust.
		return 0, unix.EIO
	}
	return copy(buf, payload), nil
}

// ReadDir returns one page of a directory's children and the index to resume
// from. more reports whether the directory has further entries.
func (c *client) ReadDir(path string, start uint32) (entries []Dirent, next uint32, more bool, err error) {
	request := []byte{opReadDir}
	request = binary.BigEndian.AppendUint32(request, start)
	request, err = appendPath(request, path)
	if err != nil {
		return nil, 0, false, err
	}
	status, payload, err := c.roundTrip(request)
	if err != nil {
		return nil, 0, false, err
	}
	if status != statusOK {
		return nil, 0, false, statusError(status)
	}
	if len(payload) < 1+4+2 {
		return nil, 0, false, unix.EIO
	}
	more = payload[0] == 1
	next = binary.BigEndian.Uint32(payload[1:5])
	count := binary.BigEndian.Uint16(payload[5:7])
	rest := payload[7:]
	entries = make([]Dirent, 0, count)
	for i := 0; i < int(count); i++ {
		if len(rest) < 2 {
			return nil, 0, false, unix.EIO
		}
		nameLen := int(binary.BigEndian.Uint16(rest[:2]))
		if nameLen == 0 || len(rest) < 2+nameLen+4+4+4+8 {
			return nil, 0, false, unix.EIO
		}
		entry := Dirent{Name: string(rest[2 : 2+nameLen])}
		rest = rest[2+nameLen:]
		entry.Mode = binary.BigEndian.Uint32(rest[0:4])
		entry.UID = binary.BigEndian.Uint32(rest[4:8])
		entry.GID = binary.BigEndian.Uint32(rest[8:12])
		entry.Size = binary.BigEndian.Uint64(rest[12:20])
		rest = rest[20:]
		entries = append(entries, entry)
	}
	if len(rest) != 0 {
		// Trailing bytes mean the page and its count disagree; refusing is the
		// only safe reading, because a partial parse would silently truncate a
		// directory.
		return nil, 0, false, unix.EIO
	}
	return entries, next, more, nil
}

// ReadLink returns a symlink's raw unresolved target. Resolution is the
// Sentry's; resolving here would let this relay decide what a link means.
func (c *client) ReadLink(path string) (string, error) {
	request, err := appendPath([]byte{opReadLink}, path)
	if err != nil {
		return "", err
	}
	status, payload, err := c.roundTrip(request)
	if err != nil {
		return "", err
	}
	if status != statusOK {
		return "", statusError(status)
	}
	if len(payload) < 2 {
		return "", unix.EIO
	}
	length := int(binary.BigEndian.Uint16(payload[:2]))
	if length == 0 || len(payload) < 2+length {
		return "", unix.EIO
	}
	return string(payload[2 : 2+length]), nil
}
