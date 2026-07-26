//go:build linux

package pgalloc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
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
	uffdioWake              = 0x8010aa02
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

type casimirFaultWakeup interface {
	continueFault(pageStart, pageSize uint64) error
	wakeFault(pageStart, pageSize uint64) error
	zeroFault(pageStart, pageSize uint64) error
	copyFault(pageStart, pageSize uint64, data []byte) error
}

type casimirFaultSyscalls interface {
	userfaultfd(flags uintptr) (uintptr, error)
	ioctl(fd uintptr, request uintptr, arg uintptr) error
	close(fd int) error
}

type linuxCasimirFaultSyscalls struct{}

func (linuxCasimirFaultSyscalls) userfaultfd(flags uintptr) (uintptr, error) {
	fd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, flags, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return fd, nil
}

func (linuxCasimirFaultSyscalls) ioctl(fd uintptr, request uintptr, arg uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, request, arg); errno != 0 {
		return errno
	}
	return nil
}

func (linuxCasimirFaultSyscalls) close(fd int) error {
	return unix.Close(fd)
}

type userfaultfdWakeup int

func (u userfaultfdWakeup) continueFault(pageStart, pageSize uint64) error {
	request := uffdioContinueRequest{Range: uffdioRange{Start: pageStart, Len: pageSize}}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(u), uffdioContinue, uintptr(unsafe.Pointer(&request))); errno != 0 {
		return errno
	}
	return nil
}

func (u userfaultfdWakeup) wakeFault(pageStart, pageSize uint64) error {
	request := uffdioRange{Start: pageStart, Len: pageSize}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(u), uffdioWake, uintptr(unsafe.Pointer(&request))); errno != 0 {
		return errno
	}
	return nil
}

func (u userfaultfdWakeup) zeroFault(pageStart, pageSize uint64) error {
	request := uffdioZeropageRequest{Range: uffdioRange{Start: pageStart, Len: pageSize}}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(u), uffdioZeropage, uintptr(unsafe.Pointer(&request))); errno != 0 {
		// The verified canonical backing may have become resident after the
		// kernel queued a MISSING event. In that exact race, map the now
		// resident page rather than failing the restore.
		if errno == unix.EEXIST {
			return u.continueFault(pageStart, pageSize)
		}
		return errno
	}
	return nil
}

func (u userfaultfdWakeup) copyFault(pageStart, pageSize uint64, data []byte) error {
	request := uffdioCopyRequest{Dst: pageStart, Src: uint64(uintptr(unsafe.Pointer(&data[0]))), Len: pageSize}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(u), uffdioCopy, uintptr(unsafe.Pointer(&request))); errno != 0 {
		// Casimir publishes verified bytes into the same shared shmem backing
		// before replying. If that publication wins the race with
		// UFFDIO_COPY, EEXIST means the page is already canonical and only
		// its missing PTE still needs to be continued.
		if errno == unix.EEXIST {
			return u.continueFault(pageStart, pageSize)
		}
		return errno
	}
	runtime.KeepAlive(data)
	return nil
}

type casimirFaultRequest struct {
	Operation string `json:"operation"`
	FaultMode string `json:"fault_mode,omitempty"`
	Offset    uint64 `json:"offset"`
	Length    uint64 `json:"length"`
}

type casimirFaultResponse struct {
	Error       string          `json:"error,omitempty"`
	Zero        bool            `json:"zero,omitempty"`
	Continue    bool            `json:"continue,omitempty"`
	Fatal       bool            `json:"fatal,omitempty"`
	FaultAction string          `json:"fault_action"`
	Data        []byte          `json:"data,omitempty"`
	Regions     []CasimirRegion `json:"regions,omitempty"`
	Layout      CasimirLayout   `json:"layout,omitempty"`
}

func validateCasimirFaultResponse(response casimirFaultResponse, mode string, pageSize uint64) (string, error) {
	reject := func(reason string) (string, error) {
		return "", fmt.Errorf("reject Casimir fault response: %s: %w", reason, unix.EINVAL)
	}
	switch response.FaultAction {
	case "wake":
		if mode != "missing" || response.Error != "" || response.Fatal || response.Zero || response.Continue ||
			len(response.Data) != 0 {
			return reject("invalid wake action")
		}
	case "copy":
		if mode != "missing" || response.Error != "" || response.Fatal || response.Zero || response.Continue ||
			uint64(len(response.Data)) != pageSize {
			return reject("invalid copy action")
		}
	case "continue":
		if mode != "minor" || response.Error != "" || response.Fatal || response.Zero || len(response.Data) != 0 {
			return reject("invalid continue action")
		}
	case "zero":
		if mode != "missing" || response.Error != "" || response.Fatal || response.Continue || len(response.Data) != 0 {
			return reject("invalid zero action")
		}
	case "fatal":
		if response.Error == "" || !response.Fatal || response.Zero || response.Continue || len(response.Data) != 0 {
			return reject("invalid fatal action")
		}
		return reject("fatal action: " + response.Error)
	default:
		return reject("missing or unknown action")
	}
	return response.FaultAction, nil
}

func resolveCasimirFault(rw *bufio.ReadWriter, wakeup casimirFaultWakeup, mode string, offset, address, pageSize uint64) (string, error) {
	if (mode != "missing" && mode != "minor") || pageSize == 0 || pageSize&(pageSize-1) != 0 {
		return "", fmt.Errorf("reject Casimir fault request mode=%q page_size=%d: %w", mode, pageSize, unix.EINVAL)
	}
	if err := json.NewEncoder(rw).Encode(casimirFaultRequest{Operation: "fault", FaultMode: mode, Offset: offset, Length: pageSize}); err != nil {
		return "", fmt.Errorf("encode Casimir fault request: %w", err)
	}
	if err := rw.Flush(); err != nil {
		return "", fmt.Errorf("flush Casimir fault request: %w", err)
	}
	var response casimirFaultResponse
	if err := json.NewDecoder(rw).Decode(&response); err != nil {
		return "", fmt.Errorf("decode Casimir fault response: %w", err)
	}
	action, err := validateCasimirFaultResponse(response, mode, pageSize)
	if err != nil {
		return "", err
	}
	pageStart := address &^ (pageSize - 1)
	switch action {
	case "wake":
		// Casimir has already materialized the verified page into the shared
		// shmem page cache. Wake the registered MISSING fault so that it
		// retries against that page; the exact retry is then authorized as a
		// resident MINOR continuation by casimirFaultTransitions.
		if err := wakeup.wakeFault(pageStart, pageSize); err != nil {
			return "", fmt.Errorf("wake Casimir published page: %w", err)
		}
	case "continue":
		if err := wakeup.continueFault(pageStart, pageSize); err != nil {
			return "", fmt.Errorf("continue Casimir resident page: %w", err)
		}
	case "zero":
		if err := wakeup.zeroFault(pageStart, pageSize); err != nil {
			return "", fmt.Errorf("install Casimir verified zero: %w", err)
		}
	case "copy":
		if err := wakeup.copyFault(pageStart, pageSize, response.Data); err != nil {
			return "", fmt.Errorf("install Casimir verified page: %w", err)
		}
	default:
		return "", fmt.Errorf("unhandled Casimir fault action %q: %w", action, unix.EINVAL)
	}
	return action, nil
}

// casimirFaultTransitions bounds the MISSING publish/retry protocol. One
// MISSING may wake one exact page range; that authorization remains pending
// until the same resident page is continued. Linux may report the post-wake
// retry with the original MISSING flag even though the shmem page is now
// resident, so an exact pending retry is presented to Casimir as MINOR. This
// permits one CONTINUE without allowing another publish/wake cycle.
type casimirFaultTransitions struct {
	pending map[uint64]uint64
}

func (t *casimirFaultTransitions) resolve(rw *bufio.ReadWriter, wakeup casimirFaultWakeup, mode string, offset, address, pageSize uint64) error {
	if pageSize == 0 || pageSize&(pageSize-1) != 0 {
		return fmt.Errorf("invalid Casimir fault page size %d: %w", pageSize, unix.EINVAL)
	}
	pageStart := address &^ (pageSize - 1)
	if mode == "missing" && t.pending[pageStart] == pageSize {
		mode = "minor"
	}
	action, err := resolveCasimirFault(rw, wakeup, mode, offset, address, pageSize)
	if err != nil {
		return err
	}
	switch {
	case mode == "missing" && action == "wake":
		if t.pending == nil {
			t.pending = make(map[uint64]uint64)
		}
		t.pending[pageStart] = pageSize
	case mode == "minor" && action == "continue":
		if t.pending[pageStart] == pageSize {
			delete(t.pending, pageStart)
		}
	}
	return nil
}

func mapCasimirFaultAlias(base *os.File, length uint64) (uintptr, error) {
	if base == nil || length == 0 || uint64(uintptr(length)) != length {
		return 0, unix.EINVAL
	}
	start, _, errno := unix.Syscall6(
		unix.SYS_MMAP,
		0,
		uintptr(length),
		unix.PROT_READ,
		unix.MAP_SHARED,
		base.Fd(),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return start, nil
}

func mapCasimirFaultAliasOneShot(base *os.File, length uint64) (uintptr, error) {
	start, mapErr := mapCasimirFaultAlias(base, length)
	closeErr := base.Close()
	if mapErr != nil {
		return 0, errors.Join(mapErr, closeErr)
	}
	if closeErr != nil {
		unix.Syscall(unix.SYS_MUNMAP, start, uintptr(length), 0)
		return 0, fmt.Errorf("retire one-shot Casimir fault base: %w", closeErr)
	}
	return start, nil
}

func verifyCasimirFaultBaseIdentity(readOnlyBase, faultBase *os.File) error {
	if readOnlyBase == nil || faultBase == nil {
		return fmt.Errorf("missing Casimir base capability: %w", unix.EINVAL)
	}
	readOnlyFlags, err := unix.FcntlInt(readOnlyBase.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("inspect read-only base capability: %w", err)
	}
	if readOnlyFlags&unix.O_ACCMODE != unix.O_RDONLY {
		return fmt.Errorf("long-lived base capability is not read-only: %w", unix.EPERM)
	}
	faultFlags, err := unix.FcntlInt(faultBase.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("inspect one-shot fault base capability: %w", err)
	}
	if faultFlags&unix.O_ACCMODE != unix.O_RDWR {
		return fmt.Errorf("one-shot fault base capability is not read-write: %w", unix.EPERM)
	}
	readOnlyInfo, err := readOnlyBase.Stat()
	if err != nil {
		return fmt.Errorf("stat read-only base capability: %w", err)
	}
	faultInfo, err := faultBase.Stat()
	if err != nil {
		return fmt.Errorf("stat one-shot fault base capability: %w", err)
	}
	if !readOnlyInfo.Mode().IsRegular() ||
		!faultInfo.Mode().IsRegular() ||
		!os.SameFile(readOnlyInfo, faultInfo) ||
		readOnlyInfo.Size() != faultInfo.Size() {
		return fmt.Errorf("one-shot fault base differs from canonical base: %w", unix.EINVAL)
	}
	return nil
}

func startCasimirFaults(dataFile *os.File, start uintptr, length uint64) (CasimirLayout, error) {
	return startCasimirFaultsWithSyscalls(dataFile, start, length, linuxCasimirFaultSyscalls{})
}

func startCasimirFaultsWithSyscalls(dataFile *os.File, start uintptr, length uint64, syscalls casimirFaultSyscalls) (CasimirLayout, error) {
	const flags = uintptr(unix.O_CLOEXEC | unix.O_NONBLOCK | uffdUserModeOnly)
	fd, err := syscalls.userfaultfd(flags)
	if err != nil {
		return CasimirLayout{}, fmt.Errorf("userfaultfd(flags=%#x): %w", flags, err)
	}
	api := uffdioAPIRequest{API: uffdAPI, Features: uffdFeatureMissingShmem | uffdFeatureMinorShmem}
	if err := syscalls.ioctl(fd, uffdioAPI, uintptr(unsafe.Pointer(&api))); err != nil {
		return CasimirLayout{}, closeCasimirFaultFD(syscalls, fd, fmt.Errorf("ioctl UFFDIO_API: %w", err))
	}
	if api.Features&uffdFeatureMissingShmem == 0 || api.Features&uffdFeatureMinorShmem == 0 {
		return CasimirLayout{}, closeCasimirFaultFD(
			syscalls,
			fd,
			fmt.Errorf("ioctl UFFDIO_API missing shmem features %#x: %w", api.Features, unix.ENOTSUP),
		)
	}
	registration := uffdioRegisterRequest{
		Range: uffdioRange{Start: uint64(start), Len: length},
		Mode:  uffdioRegisterMissing | uffdioRegisterMinor,
	}
	if err := syscalls.ioctl(fd, uffdioRegister, uintptr(unsafe.Pointer(&registration))); err != nil {
		return CasimirLayout{}, closeCasimirFaultFD(syscalls, fd, fmt.Errorf("ioctl UFFDIO_REGISTER: %w", err))
	}
	conn, err := net.FileConn(dataFile)
	dataFile.Close()
	if err != nil {
		return CasimirLayout{}, closeCasimirFaultFD(syscalls, fd, fmt.Errorf("open Casimir data connection: %w", err))
	}
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	regions, err := consumeCasimirMappings(rw, length)
	if err != nil {
		conn.Close()
		return CasimirLayout{}, closeCasimirFaultFD(syscalls, fd, fmt.Errorf("consume Casimir mappings: %w", err))
	}
	go serveCasimirFaults(int(fd), conn, rw, uint64(start), length)
	return regions, nil
}

func closeCasimirFaultFD(syscalls casimirFaultSyscalls, fd uintptr, cause error) error {
	if err := syscalls.close(int(fd)); err != nil {
		return errors.Join(cause, fmt.Errorf("close Casimir userfaultfd: %w", err))
	}
	return cause
}

// consumeCasimirMappings consumes the complete signed layout region table
// before any guest fault is served (MLAYOUT-5). The table must tile the exact
// shared-base span with valid signed states; any gap, overlap, or unknown
// state fails the restore closed before guest resume.
func consumeCasimirMappings(rw *bufio.ReadWriter, length uint64) (CasimirLayout, error) {
	if err := json.NewEncoder(rw).Encode(casimirFaultRequest{Operation: "mappings"}); err != nil {
		return CasimirLayout{}, err
	}
	if err := rw.Flush(); err != nil {
		return CasimirLayout{}, err
	}
	var response casimirFaultResponse
	if err := json.NewDecoder(rw).Decode(&response); err != nil {
		return CasimirLayout{}, err
	}
	if response.Error != "" || response.Layout.Version != 2 || response.Layout.PageSize == 0 || len(response.Layout.AddressSpaces) == 0 || len(response.Regions) != 0 {
		log.Warningf("Casimir LLML2 layout rejected: error=%q version=%d address_spaces=%d legacy_regions=%d", response.Error, response.Layout.Version, len(response.Layout.AddressSpaces), len(response.Regions))
		return CasimirLayout{}, unix.EINVAL
	}
	var previous CasimirAuthorityID
	for i, addressSpace := range response.Layout.AddressSpaces {
		if addressSpace.MinAddr >= addressSpace.MaxAddr || len(addressSpace.Regions) == 0 || (i != 0 && string(previous[:]) >= string(addressSpace.Identity[:])) {
			return CasimirLayout{}, unix.EINVAL
		}
		next := addressSpace.MinAddr
		for _, region := range addressSpace.Regions {
			if region.GuestStart != next || region.Length == 0 || region.State < 1 || region.State > 3 ||
				region.Protection&^uint8(7) != 0 || region.Flags&^uint8(3) != 0 ||
				region.GuestStart > ^uint64(0)-region.Length {
				return CasimirLayout{}, unix.EINVAL
			}
			if region.State == 1 && region.BackingKind == CasimirBackingNone ||
				region.State != 1 && (region.BackingKind != CasimirBackingNone || region.Backing != (CasimirAuthorityID{}) || region.ObjectOffset != 0) {
				return CasimirLayout{}, unix.EINVAL
			}
			if region.BackingKind == CasimirBackingBaseMemory && region.ObjectOffset+region.Length > length {
				return CasimirLayout{}, unix.EINVAL
			}
			next += region.Length
		}
		if next != addressSpace.MaxAddr {
			return CasimirLayout{}, unix.EINVAL
		}
		previous = addressSpace.Identity
	}
	log.Infof("Casimir signed LLML2 layout consumed: %d address spaces", len(response.Layout.AddressSpaces))
	return response.Layout.Clone(), nil
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
	transitions := casimirFaultTransitions{}
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
		if err := transitions.resolve(rw, userfaultfdWakeup(uffd), mode, offset, address, pageSize); err != nil {
			log.Warningf("Casimir fault resolution failed: %v", err)
			return
		}
	}
}
