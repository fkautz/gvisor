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
	"path"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// EVERY MUTATION IS WRITTEN OUT EXPLICITLY RATHER THAN EMBEDDED.
//
// lisafs.ControlFDImpl has 19 methods and OpenFDImpl about 10; a read-only
// content-addressed root genuinely implements a handful. Embedding the
// interface to satisfy the compiler is the obvious shortcut and it is the wrong
// one: an unreached operation then PANICS inside the gofer, and a panicking
// gofer reaches the workload as an unexplained EIO with nothing in any log
// naming the cause. An explicit EROFS is a decision a reviewer can check.
//
// SupportedMessages already stops most of these being reached at all -- the
// framework rejects an unlisted MID before dispatch (pkg/lisafs/connection.go)
// -- so these bodies are the second line, not the first.

// connection implements lisafs.ConnectionImpl for one served root.
type connection struct {
	client *client
}

var _ lisafs.ConnectionImpl = (*connection)(nil)

// Mount attaches the served root.
func (c *connection) Mount(conn *lisafs.Connection, mountNode *lisafs.Node) (*lisafs.ControlFD, lisafs.Statx, int, error) {
	// THE ROOT IS THE EMPTY PATH, not ".". LLIFS canonical paths are relative
	// with no leading separator, and normalization drops "." components, so the
	// root entry the store publishes is literally the zero-length path. Sending
	// "." asks for a child named "." that no rootfs contains, and the store
	// answers "not found" -- which reaches the operator as "mounting root with
	// overlay: no such file or directory", naming nothing.
	attr, err := c.client.Stat("")
	if err != nil {
		return nil, lisafs.Statx{}, -1, err
	}
	root := &controlFD{conn: c, path: ""}
	mountNode.IncRef() // Ref is transferred to the ControlFD.
	root.ControlFD.Init(conn, mountNode, linux.FileMode(attr.Mode), root)
	// No host FD is donated: there is no host file behind these bytes, which is
	// the whole reason this backend exists.
	return root.FD(), statxFromAttr(attr), -1, nil
}

// MaxMessageSize implements lisafs.ConnectionImpl.MaxMessageSize.
func (c *connection) MaxMessageSize() uint32 { return lisafs.MaxMessageSize() }

// SupportedMessages declares exactly what this backend answers.
//
// IT IS BOUNDED BY WHAT THE STORE CAN ANSWER, not by what lisafs defines.
// Listing a message the store cannot serve would move the failure from a clean
// framework rejection into this package, which is the wrong place for it.
func (c *connection) SupportedMessages() []lisafs.MID {
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
		lisafs.FStat,
		lisafs.Walk,
		lisafs.WalkStat,
		lisafs.OpenAt,
		lisafs.FStatFS,
		lisafs.ReadLinkAt,
		lisafs.Getdents64,
		lisafs.PRead,
		lisafs.Close,
		lisafs.Flush,
		lisafs.FSync,
	}
}

func statxFromAttr(attr Attr) lisafs.Statx {
	return lisafs.Statx{
		Mask:    unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_NLINK,
		Mode:    uint16(attr.Mode),
		UID:     attr.UID,
		GID:     attr.GID,
		Size:    attr.Size,
		Nlink:   1,
		Blksize: 4096,
	}
}

func direntType(mode uint32) uint8 {
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return unix.DT_DIR
	case unix.S_IFREG:
		return unix.DT_REG
	case unix.S_IFLNK:
		return unix.DT_LNK
	default:
		return unix.DT_UNKNOWN
	}
}

// joinPath keeps store paths normalized and rooted. It is deliberately strict:
// a component that escapes the root is refused rather than clamped, because
// clamping would silently serve a different file than the one asked for.
func joinPath(base, name string) (string, error) {
	if name == "" || name == "." || strings.Contains(name, "/") {
		return "", unix.EINVAL
	}
	if name == ".." {
		return "", unix.EPERM
	}
	joined := path.Join(base, name)
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", unix.EPERM
	}
	return joined, nil
}

// controlFD is one node in the served tree.
type controlFD struct {
	lisafs.ControlFD
	conn *connection
	path string
}

var _ lisafs.ControlFDImpl = (*controlFD)(nil)

func (fd *controlFD) FD() *lisafs.ControlFD { return &fd.ControlFD }

func (fd *controlFD) Close() {}

func (fd *controlFD) Stat() (lisafs.Statx, error) {
	attr, err := fd.conn.client.Stat(fd.path)
	if err != nil {
		return lisafs.Statx{}, err
	}
	return statxFromAttr(attr), nil
}

func (fd *controlFD) Walk(name string) (*lisafs.ControlFD, lisafs.Statx, error) {
	child, err := joinPath(fd.path, name)
	if err != nil {
		return nil, lisafs.Statx{}, err
	}
	attr, err := fd.conn.client.Stat(child)
	if err != nil {
		return nil, lisafs.Statx{}, err
	}
	// EVERY WALKED CHILD NEEDS ITS OWN Node. A Node is the server-side identity
	// of a file and the client caches against it, so initializing a child FD
	// with its PARENT's Node makes every sibling the same file: walk two names
	// in one directory and the second resolves to the first one's contents,
	// size and all. Only a fixture with two files in one directory can catch
	// that -- a one-file rootfs always agrees with itself.
	parentNode := fd.Node()
	var childNode *lisafs.Node
	parentNode.WithChildrenMu(func() {
		if childNode = parentNode.LookupChildLocked(name); childNode == nil {
			childNode = &lisafs.Node{}
			// InitLocked transfers a ref to us; the else branch takes its own.
			childNode.InitLocked(name, parentNode)
		} else {
			childNode.IncRef()
		}
	})
	walked := &controlFD{conn: fd.conn, path: child}
	walked.ControlFD.Init(fd.Conn(), childNode, linux.FileMode(attr.Mode), walked)
	return walked.FD(), statxFromAttr(attr), nil
}

// WalkStat walks several components, stopping at a symlink.
//
// STOPPING AT A SYMLINK IS REQUIRED, not an optimization: resolution belongs to
// the Sentry, and continuing through a link here would let this backend decide
// what the link means.
func (fd *controlFD) WalkStat(pathComponents lisafs.StringArray, recordStat func(lisafs.Statx)) error {
	current := fd.path
	for i, name := range pathComponents {
		if i == 0 && name == "" {
			attr, err := fd.conn.client.Stat(current)
			if err != nil {
				return err
			}
			recordStat(statxFromAttr(attr))
			continue
		}
		next, err := joinPath(current, name)
		if err != nil {
			return err
		}
		attr, err := fd.conn.client.Stat(next)
		if err != nil {
			// A walk that cannot complete stops successfully with what it has;
			// the client retries component by component.
			return nil
		}
		recordStat(statxFromAttr(attr))
		current = next
		if attr.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil
		}
	}
	return nil
}

func (fd *controlFD) Open(flags uint32) (*lisafs.OpenFD, int, error) {
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		// The served root is read-only. Refusing here rather than at the first
		// write keeps the failure at the point the intent is stated.
		return nil, -1, unix.EROFS
	}
	opened := &openFD{conn: fd.conn, path: fd.path}
	opened.OpenFD.Init(fd.FD(), flags, opened)
	return opened.FD(), -1, nil
}

func (fd *controlFD) StatFS() (lisafs.StatFS, error) {
	// A content-addressed store has no meaningful free space or inode count;
	// reporting zeroes is honest rather than inventing capacity.
	return lisafs.StatFS{
		Type:      linux.V9FS_MAGIC,
		BlockSize: 4096,
	}, nil
}

func (fd *controlFD) Readlink(getLinkBuf func(uint32) []byte) (uint16, error) {
	target, err := fd.conn.client.ReadLink(fd.path)
	if err != nil {
		return 0, err
	}
	buf := getLinkBuf(uint32(len(target)))
	return uint16(copy(buf, target)), nil
}

// --- Everything below is refused. Read-only store, no host files, no sockets.

func (fd *controlFD) SetStat(stat lisafs.SetStatReq) (uint32, error) { return 0, unix.EROFS }

func (fd *controlFD) OpenCreate(mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string, flags uint32) (*lisafs.ControlFD, lisafs.Statx, *lisafs.OpenFD, int, error) {
	return nil, lisafs.Statx{}, nil, -1, unix.EROFS
}

func (fd *controlFD) Mkdir(mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string) (*lisafs.ControlFD, lisafs.Statx, error) {
	return nil, lisafs.Statx{}, unix.EROFS
}

func (fd *controlFD) Mknod(mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string, minor uint32, major uint32) (*lisafs.ControlFD, lisafs.Statx, error) {
	return nil, lisafs.Statx{}, unix.EROFS
}

func (fd *controlFD) Symlink(name string, target string, uid lisafs.UID, gid lisafs.GID) (*lisafs.ControlFD, lisafs.Statx, error) {
	return nil, lisafs.Statx{}, unix.EROFS
}

func (fd *controlFD) Link(dir lisafs.ControlFDImpl, name string) (*lisafs.ControlFD, lisafs.Statx, error) {
	return nil, lisafs.Statx{}, unix.EROFS
}

func (fd *controlFD) Unlink(name string, flags uint32) error { return unix.EROFS }

func (fd *controlFD) RenameAt(oldName string, newDir lisafs.ControlFDImpl, newName string) error {
	return unix.EROFS
}

func (fd *controlFD) RenameAt2(oldName string, newDir lisafs.ControlFDImpl, newName string, flags uint32) error {
	return unix.EROFS
}

// Renamed cannot happen on a read-only root, but the notification is not an
// operation to refuse -- it is the framework telling us about state we do not
// keep. Doing nothing is correct; returning an error is not an option here.
func (fd *controlFD) Renamed() {}

// Extended attributes are not served. The store's logical rootfs carries xattrs
// in its own metadata, but nothing publishes them over this protocol yet, so
// ENODATA ("no such attribute") is the honest answer for a read and EROFS for a
// write. Reporting an empty list rather than an error would tell the Sentry the
// file HAS no attributes, which is a different and unverified claim.
func (fd *controlFD) GetXattr(name string, size uint32, getValueBuf func(uint32) []byte) (uint16, error) {
	return 0, unix.ENODATA
}

func (fd *controlFD) SetXattr(name string, value string, flags uint32) error { return unix.EROFS }

func (fd *controlFD) ListXattr(size uint64) (lisafs.StringArray, error) {
	return nil, unix.ENOTSUP
}

func (fd *controlFD) RemoveXattr(name string) error { return unix.EROFS }

// Sockets are not merely unimplemented here; a rootfs backend has no business
// answering them, so ENOTSUP rather than EROFS.
func (fd *controlFD) Connect(sockType uint32) (int, error) { return -1, unix.ENOTSUP }

func (fd *controlFD) ConnectWithCreds(sockType uint32, uid lisafs.UID, gid lisafs.GID) (int, error) {
	return -1, unix.ENOTSUP
}

func (fd *controlFD) BindAt(name string, sockType uint32, mode linux.FileMode, uid lisafs.UID, gid lisafs.GID) (*lisafs.ControlFD, lisafs.Statx, *lisafs.BoundSocketFD, int, error) {
	return nil, lisafs.Statx{}, nil, -1, unix.ENOTSUP
}

// openFD is one open handle on a served node.
type openFD struct {
	lisafs.OpenFD
	conn *connection
	path string

	// next is the store's resume index, not a byte offset, so it lives here
	// rather than being derived from the dirent Off.
	next uint32
	done bool
}

var _ lisafs.OpenFDImpl = (*openFD)(nil)

func (fd *openFD) FD() *lisafs.OpenFD { return &fd.OpenFD }

func (fd *openFD) Close() {}

func (fd *openFD) Stat() (lisafs.Statx, error) {
	attr, err := fd.conn.client.Stat(fd.path)
	if err != nil {
		return lisafs.Statx{}, err
	}
	return statxFromAttr(attr), nil
}

func (fd *openFD) Read(buf []byte, off uint64) (uint64, error) {
	n, err := fd.conn.client.ReadAt(fd.path, buf, off)
	if err != nil {
		return 0, err
	}
	return uint64(n), nil
}

// Getdent64 pages through the store's enumeration.
//
// seek0 restarts; otherwise it resumes from where the previous call stopped.
// The resume index is the store's, not a byte offset, so it is kept on the FD
// rather than derived from Off.
func (fd *openFD) Getdent64(count uint32, seek0 bool, recordDirent func(lisafs.Dirent64)) error {
	if seek0 {
		fd.next = 0
		fd.done = false
	}
	if fd.done {
		return nil
	}
	var emitted uint32
	for emitted < count && !fd.done {
		entries, next, more, err := fd.conn.client.ReadDir(fd.path, fd.next)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fd.done = true
			break
		}
		for _, entry := range entries {
			if emitted == count {
				break
			}
			recordDirent(lisafs.Dirent64{
				Ino:  primitive.Uint64(0),
				Off:  primitive.Uint64(uint64(fd.next) + 1),
				Type: primitive.Uint8(direntType(entry.Mode)),
				Name: lisafs.SizedString(entry.Name),
			})
			fd.next++
			emitted++
		}
		if !more {
			fd.done = true
		} else if fd.next < next {
			fd.next = next
		}
	}
	return nil
}

func (fd *openFD) Sync() error  { return nil }
func (fd *openFD) Flush() error { return nil }
func (fd *openFD) Renamed()     {}

func (fd *openFD) Write(buf []byte, off uint64) (uint64, error) { return 0, unix.EROFS }

func (fd *openFD) Allocate(mode, off, length uint64) error { return unix.EROFS }
