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

	// opReadCopyUp is opRead for bytes an overlay copy-up is fetching.
	opReadCopyUp = 7
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

	// Ino is the store's stable identifier for this file, never zero.
	//
	// IT IS LOAD-BEARING, not decoration. The Sentry's gofer client keys its
	// inode cache on inoKey{Ino, DevMinor, DevMajor} and shares one inode
	// across every dentry with an equal key, so publishing zero for every file
	// makes every file in the mount the same file -- the second name walked in
	// a directory serves the first one's contents and size. A content-addressed
	// store has no host inode, so this comes from the store's canonical entry
	// order instead.
	Ino uint64
}

// Dirent is one directory entry as the store reports it.
type Dirent struct {
	Name string
	Mode uint32
	UID  uint32
	GID  uint32
	Size uint64
	Ino  uint64
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

// appendPath encodes one path. THE EMPTY PATH IS VALID AND MEANS THE ROOT: an
// LLIFS path is relative with no leading separator, so the served root has no
// name at all.
func appendPath(request []byte, path string) ([]byte, error) {
	if len(path) > maxPathBytes {
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
	if len(payload) < 8+4+4+4+1+8 {
		return Attr{}, unix.EIO
	}
	ino := binary.BigEndian.Uint64(payload[21:29])
	if ino == 0 {
		// Zero is the store saying it has no identifier, and it is the exact
		// value that aliases every file onto one inode. Refuse rather than serve
		// a name whose contents cannot be trusted to be its own.
		return Attr{}, unix.EIO
	}
	return Attr{
		Size:    binary.BigEndian.Uint64(payload[0:8]),
		Mode:    binary.BigEndian.Uint32(payload[8:12]),
		UID:     binary.BigEndian.Uint32(payload[12:16]),
		GID:     binary.BigEndian.Uint32(payload[16:20]),
		Regular: payload[20] == 1,
		Ino:     ino,
	}, nil
}

// ReadAt fills buf from path at off, returning the number of bytes published.
//
// A SHORT RESULT IS NOT AN ERROR AND ZERO BYTES IS NOT SUCCESS: the protocol
// cannot express an empty successful payload, so a request that yields nothing
// is a refusal rather than an EOF.
func (c *client) ReadAt(path string, buf []byte, off uint64) (int, error) {
	return c.ReadAtHinted(path, buf, off, false)
}

// ReadAtHinted is ReadAt, telling the store whether this read is an overlay
// copy-up. The store needs it to account for the fetch separately, and to
// decide whether to allow it at all.
func (c *client) ReadAtHinted(path string, buf []byte, off uint64, copyUp bool) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	length := len(buf)
	if length > maxReadBytes {
		length = maxReadBytes
	}
	// opReadCopyUp is a distinct opcode rather than a flag byte so an older
	// store rejects it outright instead of silently mis-accounting a copy-up
	// as a foreground read, which is the whole thing being fixed.
	opcode := byte(opRead)
	if copyUp {
		opcode = opReadCopyUp
	}
	request := []byte{opcode}
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
		if nameLen == 0 || len(rest) < 2+nameLen+4+4+4+8+8 {
			return nil, 0, false, unix.EIO
		}
		entry := Dirent{Name: string(rest[2 : 2+nameLen])}
		rest = rest[2+nameLen:]
		entry.Mode = binary.BigEndian.Uint32(rest[0:4])
		entry.UID = binary.BigEndian.Uint32(rest[4:8])
		entry.GID = binary.BigEndian.Uint32(rest[8:12])
		entry.Size = binary.BigEndian.Uint64(rest[12:20])
		entry.Ino = binary.BigEndian.Uint64(rest[20:28])
		if entry.Ino == 0 {
			return nil, 0, false, unix.EIO
		}
		rest = rest[28:]
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

// fdConn is a blocking byte stream over an already-connected raw descriptor.
//
// IT DELIBERATELY AVOIDS net.FileConn. That constructor issues getsockopt to
// learn the socket type and then registers the descriptor with Go's netpoller,
// and the gofer installs its seccomp filter before mount dispatch -- so the
// very first getsockopt killed the gofer with SIGSYS. That produces no panic
// and no log line: the Sentry saw "connection reset by peer" and the operator
// saw "mounting root with overlay: input/output error". The cause was read out
// of a kernel audit record (type=1326 sig=31 syscall=55), not guessed.
//
// read(2) and write(2) on a connected blocking descriptor need nothing the
// stock gofer filter does not already allow.
type fdConn struct {
	fd int
}

func (c *fdConn) Read(buf []byte) (int, error) {
	for {
		n, err := unix.Read(c.fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 && len(buf) > 0 {
			// A stream socket returns zero only at end of stream. Reporting it
			// as a successful empty read would spin io.ReadFull forever.
			return 0, io.EOF
		}
		return n, nil
	}
}

func (c *fdConn) Write(buf []byte) (int, error) {
	written := 0
	for written < len(buf) {
		n, err := unix.Write(c.fd, buf[written:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}
