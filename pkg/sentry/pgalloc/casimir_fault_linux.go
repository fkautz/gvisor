//go:build linux

package pgalloc

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	uffdAPI                 = 0xAA
	uffdEventPagefault      = 0x12
	uffdUserModeOnly        = 1
	uffdFeatureMissingShmem = 1 << 5
	uffdFeatureMinorShmem   = 1 << 10
	uffdioAPI               = 0xc018aa3f
	uffdioRegister          = 0xc020aa00
	uffdioCopy              = 0xc028aa03
	uffdioZeropage          = 0xc020aa04
	uffdioContinue          = 0xc020aa07
	uffdioRegisterMissing   = 1
	uffdioRegisterMinor     = 4
	uffdPagefaultFlagMinor  = 1 << 2
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

type uffdioCopyRequest struct {
	Dst, Src, Len, Mode uint64
	Copy                int64
}

type uffdioContinueRequest struct {
	Range  uffdioRange
	Mode   uint64
	Mapped int64
}

type casimirFaultRequest struct {
	Operation string `json:"operation"`
	FaultMode string `json:"fault_mode,omitempty"`
	Offset    uint64 `json:"offset"`
	Length    uint64 `json:"length"`
}

type casimirRegion struct {
	GuestStart uint64 `json:"guest_start"`
	Length     uint64 `json:"length"`
	State      uint8  `json:"state"`
	Protection uint8  `json:"protection"`
	Flags      uint8  `json:"flags"`
}

type casimirFaultResponse struct {
	Error    string          `json:"error,omitempty"`
	Zero     bool            `json:"zero,omitempty"`
	Continue bool            `json:"continue,omitempty"`
	Data     []byte          `json:"data,omitempty"`
	Regions  []casimirRegion `json:"regions,omitempty"`
}

func startCasimirFaults(dataFile *os.File, start uintptr, length uint64) error {
	fd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, uintptr(unix.O_CLOEXEC|unix.O_NONBLOCK|uffdUserModeOnly), 0, 0)
	if errno != 0 {
		return errno
	}
	api := uffdioAPIRequest{API: uffdAPI, Features: uffdFeatureMissingShmem | uffdFeatureMinorShmem}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uffdioAPI, uintptr(unsafe.Pointer(&api))); errno != 0 {
		unix.Close(int(fd))
		return errno
	}
	if api.Features&uffdFeatureMissingShmem == 0 || api.Features&uffdFeatureMinorShmem == 0 {
		unix.Close(int(fd))
		return unix.ENOTSUP
	}
	registration := uffdioRegisterRequest{Range: uffdioRange{Start: uint64(start), Len: length}, Mode: uffdioRegisterMissing | uffdioRegisterMinor}
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
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if err := consumeCasimirMappings(rw, length); err != nil {
		conn.Close()
		unix.Close(int(fd))
		return err
	}
	go serveCasimirFaults(int(fd), conn, rw, uint64(start), length)
	return nil
}

// consumeCasimirMappings consumes the complete signed layout region table
// before any guest fault is served (MLAYOUT-5). The table must tile the exact
// shared-base span with valid signed states; any gap, overlap, or unknown
// state fails the restore closed before guest resume.
func consumeCasimirMappings(rw *bufio.ReadWriter, length uint64) error {
	if err := json.NewEncoder(rw).Encode(casimirFaultRequest{Operation: "mappings"}); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}
	var response casimirFaultResponse
	if err := json.NewDecoder(rw).Decode(&response); err != nil {
		return err
	}
	if response.Error != "" || len(response.Regions) == 0 {
		log.Warningf("Casimir mapping table rejected: error=%q regions=%d", response.Error, len(response.Regions))
		return unix.EINVAL
	}
	var next uint64
	for _, region := range response.Regions {
		if region.GuestStart != next || region.Length == 0 || region.State < 1 || region.State > 3 {
			log.Warningf("Casimir mapping table is not a contiguous signed tiling at %#x", region.GuestStart)
			return unix.EINVAL
		}
		next += region.Length
	}
	if next != length {
		log.Warningf("Casimir mapping table covers %#x bytes, want %#x", next, length)
		return unix.EINVAL
	}
	log.Infof("Casimir signed mapping table consumed: %d regions over %#x bytes", len(response.Regions), length)
	return nil
}

func serveCasimirFaults(uffd int, conn net.Conn, rw *bufio.ReadWriter, start, length uint64) {
	defer unix.Close(uffd)
	defer conn.Close()
	// Any loss or rejection of the verifier channel leaves a missing page
	// unresolved. Terminate the Sentry instead of permitting zero-fill or a
	// private fallback.
	defer unix.Kill(os.Getpid(), unix.SIGKILL)
	var msg [32]byte
	pageSize := uint64(os.Getpagesize())
	for {
		if _, err := unix.Poll([]unix.PollFd{{Fd: int32(uffd), Events: unix.POLLIN}}, -1); err != nil {
			if err == unix.EINTR {
				continue
			}
			log.Warningf("Casimir userfaultfd poll failed: %v", err)
			return
		}
		n, err := unix.Read(uffd, msg[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != len(msg) {
			log.Warningf("Casimir userfaultfd read failed: n=%d err=%v", n, err)
			return
		}
		if msg[0] != uffdEventPagefault {
			log.Warningf("Casimir userfaultfd unexpected event: %#x", msg[0])
			return
		}
		address := *(*uint64)(unsafe.Pointer(&msg[16]))
		if address < start || address >= start+length {
			log.Warningf("Casimir userfaultfd address outside base: %#x", address)
			return
		}
		offset := address - start
		flags := *(*uint64)(unsafe.Pointer(&msg[8]))
		mode := "missing"
		if flags&uffdPagefaultFlagMinor != 0 {
			mode = "minor"
		}
		if err := json.NewEncoder(rw).Encode(casimirFaultRequest{Operation: "fault", FaultMode: mode, Offset: offset, Length: pageSize}); err != nil {
			log.Warningf("Casimir fault request failed: %v", err)
			return
		}
		if err := rw.Flush(); err != nil {
			log.Warningf("Casimir fault request flush failed: %v", err)
			return
		}
		var response casimirFaultResponse
		if err := json.NewDecoder(rw).Decode(&response); err != nil || response.Error != "" {
			log.Warningf("Casimir fault rejected: response=%q err=%v", response.Error, err)
			return
		}
		pageStart := address &^ (pageSize - 1)
		if response.Continue {
			if mode != "minor" {
				log.Warningf("Casimir continuation for non-minor fault at %#x", address)
				return
			}
			request := uffdioContinueRequest{Range: uffdioRange{Start: pageStart, Len: pageSize}}
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(uffd), uffdioContinue, uintptr(unsafe.Pointer(&request))); errno != 0 {
				log.Warningf("Casimir resident-page continuation failed: %v", errno)
				return
			}
			continue
		}
		if mode != "missing" {
			log.Warningf("Casimir non-continuation response for minor fault at %#x", address)
			return
		}
		if response.Zero {
			zero := uffdioZeropageRequest{Range: uffdioRange{Start: pageStart, Len: pageSize}}
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(uffd), uffdioZeropage, uintptr(unsafe.Pointer(&zero))); errno != 0 {
				log.Warningf("Casimir verified-zero installation failed: %v", errno)
				return
			}
			continue
		}
		if uint64(len(response.Data)) != pageSize {
			log.Warningf("Casimir verified-page response length %d, want %d", len(response.Data), pageSize)
			return
		}
		copy := uffdioCopyRequest{Dst: pageStart, Src: uint64(uintptr(unsafe.Pointer(&response.Data[0]))), Len: pageSize}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(uffd), uffdioCopy, uintptr(unsafe.Pointer(&copy))); errno != 0 {
			log.Warningf("Casimir verified-page installation failed: %v", errno)
			return
		}
		runtime.KeepAlive(response.Data)
	}
}
