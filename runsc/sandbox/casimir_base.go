package sandbox

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func consumeVerifiedInheritedFaultBaseImage(fd int, expected *baseImageIdentity) (*os.File, baseImageIdentity, error) {
	file, identity, duplicateErr := duplicateVerifiedInheritedBaseImage(fd, unix.O_RDWR, expected)
	closeErr := unix.Close(fd)
	if duplicateErr != nil {
		return nil, baseImageIdentity{}, errors.Join(duplicateErr, closeErr)
	}
	if closeErr != nil {
		file.Close()
		return nil, baseImageIdentity{}, fmt.Errorf("retire inherited one-shot fault base: %w", closeErr)
	}
	return file, identity, nil
}

func exactInheritedFD(name string, expected int) (int, error) {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value != expected {
		return -1, fmt.Errorf("%s must bind exact inherited descriptor %d", name, expected)
	}
	return value, nil
}

func duplicateVerifiedInheritedBaseImage(fd int, access int, expected *baseImageIdentity) (*os.File, baseImageIdentity, error) {
	if fd < 0 || (access != unix.O_RDONLY && access != unix.O_RDWR) {
		return nil, baseImageIdentity{}, fmt.Errorf("invalid inherited base capability")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return nil, baseImageIdentity{}, err
	}
	if flags&unix.O_ACCMODE != access {
		return nil, baseImageIdentity{}, fmt.Errorf("inherited base access mode %#x, want %#x", flags&unix.O_ACCMODE, access)
	}
	dupFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, baseImageIdentity{}, err
	}
	file := os.NewFile(uintptr(dupFD), "inherited-canonical-base")
	var opened unix.Stat_t
	if err := unix.Fstat(dupFD, &opened); err != nil {
		file.Close()
		return nil, baseImageIdentity{}, err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG {
		file.Close()
		return nil, baseImageIdentity{}, fmt.Errorf("inherited base is not a regular file")
	}
	identity := baseImageIdentity{
		dev:  uint64(opened.Dev),
		ino:  opened.Ino,
		size: opened.Size,
		mode: opened.Mode,
	}
	if expected != nil && identity != *expected {
		file.Close()
		return nil, baseImageIdentity{}, fmt.Errorf("inherited base differs from verified canonical authority")
	}
	return file, identity, nil
}

type baseImageIdentity struct {
	dev  uint64
	ino  uint64
	size int64
	mode uint32
}
