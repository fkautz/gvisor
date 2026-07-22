//go:build linux

package pgalloc

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	uffdAPI                 = 0xAA
	uffdEventPagefault      = 0x12
	uffdUserModeOnly        = 1
	uffdFeatureMissingShmem = 1 << 5
	uffdioAPI               = 0xc018aa3f
	uffdioRegister          = 0xc020aa00
	uffdioWake              = 0x8010aa02
	uffdioZeropage          = 0xc020aa04
	uffdioRegisterMissing   = 1
)

type uffdioAPIRequest struct {
	API, Features, IOCTLs uint64
}

type uffdioRange struct {
	Start, Len uint64
}

type uffdioRegisterRequest struct {
	Range        uffdioRange
	Mode, IOCTLs uint64
}

type uffdioZeropageRequest struct {
	Range    uffdioRange
	Mode     uint64
	Zeropage int64
}

type casimirFaultRequest struct {
	Operation string `json:"operation"`
	Offset    uint64 `json:"offset"`
	Length    uint64 `json:"length"`
}

type casimirFaultResponse struct {
	Error string `json:"error,omitempty"`
	Zero  bool   `json:"zero,omitempty"`
}

func startCasimirFaults(dataFile *os.File, start uintptr, length uint64) error {
	fd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, uintptr(unix.O_CLOEXEC|unix.O_NONBLOCK|uffdUserModeOnly), 0, 0)
	if errno != 0 {
		return errno
	}
	api := uffdioAPIRequest{API: uffdAPI, Features: uffdFeatureMissingShmem}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uffdioAPI, uintptr(unsafe.Pointer(&api))); errno != 0 {
		unix.Close(int(fd))
		return errno
	}
	if api.Features&uffdFeatureMissingShmem == 0 {
		unix.Close(int(fd))
		return unix.ENOTSUP
	}
	registration := uffdioRegisterRequest{Range: uffdioRange{Start: uint64(start), Len: length}, Mode: uffdioRegisterMissing}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uffdioRegister, uintptr(unsafe.Pointer(&registration))); errno != 0 {
		unix.Close(int(fd))
		return errno
	}
	conn, err := net.FileConn(dataFile)
	dataFile.Close()
	if err != nil {
		unix.Close(int(fd))
		return err
	}
	go serveCasimirFaults(int(fd), conn, uint64(start), length)
	return nil
}

func serveCasimirFaults(uffd int, conn net.Conn, start, length uint64) {
	defer unix.Close(uffd)
	defer conn.Close()
	// Any loss or rejection of the verifier channel leaves a missing page
	// unresolved. Terminate the Sentry instead of permitting zero-fill or a
	// private fallback.
	defer unix.Kill(os.Getpid(), unix.SIGKILL)
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	var msg [32]byte
	pageSize := uint64(os.Getpagesize())
	for {
		if _, err := unix.Poll([]unix.PollFd{{Fd: int32(uffd), Events: unix.POLLIN}}, -1); err != nil {
			return
		}
		n, err := unix.Read(uffd, msg[:])
		if err != nil || n != len(msg) {
			return
		}
		if msg[0] != uffdEventPagefault {
			return
		}
		address := *(*uint64)(unsafe.Pointer(&msg[16]))
		if address < start || address >= start+length {
			return
		}
		offset := address - start
		if err := json.NewEncoder(rw).Encode(casimirFaultRequest{Operation: "fault", Offset: offset, Length: pageSize}); err != nil {
			return
		}
		if err := rw.Flush(); err != nil {
			return
		}
		var response casimirFaultResponse
		if err := json.NewDecoder(rw).Decode(&response); err != nil || response.Error != "" {
			return
		}
		pageStart := address &^ (pageSize - 1)
		if response.Zero {
			zero := uffdioZeropageRequest{Range: uffdioRange{Start: pageStart, Len: pageSize}}
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(uffd), uffdioZeropage, uintptr(unsafe.Pointer(&zero))); errno != 0 {
				return
			}
			continue
		}
		wake := uffdioRange{Start: pageStart, Len: pageSize}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(uffd), uffdioWake, uintptr(unsafe.Pointer(&wake))); errno != 0 {
			return
		}
	}
}
