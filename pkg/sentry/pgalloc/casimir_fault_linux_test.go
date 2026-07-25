//go:build linux

package pgalloc

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

type recordingCasimirWakeup struct {
	calls     []string
	pageStart uint64
	pageSize  uint64
	data      []byte
}

type recordingCasimirFaultSyscalls struct {
	openErr       error
	failRequest   uintptr
	openedFlags   uintptr
	ioctlRequests []uintptr
	closedFDs     []int
}

func (s *recordingCasimirFaultSyscalls) userfaultfd(flags uintptr) (uintptr, error) {
	s.openedFlags = flags
	if s.openErr != nil {
		return 0, s.openErr
	}
	return 42, nil
}

func (s *recordingCasimirFaultSyscalls) ioctl(_ uintptr, request uintptr, arg uintptr) error {
	s.ioctlRequests = append(s.ioctlRequests, request)
	if request == uffdioAPI {
		api := (*uffdioAPIRequest)(unsafe.Pointer(arg))
		api.Features |= uffdFeatureMissingShmem | uffdFeatureMinorShmem
	}
	if request == s.failRequest {
		return unix.EPERM
	}
	return nil
}

func (s *recordingCasimirFaultSyscalls) close(fd int) error {
	s.closedFDs = append(s.closedFDs, fd)
	return nil
}

func TestStartCasimirFaultsLabelsEPERMBoundaryAndClosesOpenedFD(t *testing.T) {
	tests := []struct {
		name         string
		syscalls     *recordingCasimirFaultSyscalls
		wantBoundary string
		wantRequests []uintptr
		wantClosed   []int
	}{
		{
			name:         "userfaultfd syscall",
			syscalls:     &recordingCasimirFaultSyscalls{openErr: unix.EPERM},
			wantBoundary: "userfaultfd",
		},
		{
			name:         "UFFDIO_API ioctl",
			syscalls:     &recordingCasimirFaultSyscalls{failRequest: uffdioAPI},
			wantBoundary: "UFFDIO_API",
			wantRequests: []uintptr{uffdioAPI},
			wantClosed:   []int{42},
		},
		{
			name:         "UFFDIO_REGISTER ioctl",
			syscalls:     &recordingCasimirFaultSyscalls{failRequest: uffdioRegister},
			wantBoundary: "UFFDIO_REGISTER",
			wantRequests: []uintptr{uffdioAPI, uffdioRegister},
			wantClosed:   []int{42},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := startCasimirFaultsWithSyscalls(nil, 0x1000, 4096, test.syscalls)
			if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), test.wantBoundary) {
				t.Fatalf("startCasimirFaultsWithSyscalls() error = %v, want EPERM at %s", err, test.wantBoundary)
			}
			if got, want := test.syscalls.openedFlags, uintptr(unix.O_CLOEXEC|unix.O_NONBLOCK|uffdUserModeOnly); got != want {
				t.Fatalf("userfaultfd flags = %#x, want %#x", got, want)
			}
			if !equalUintptrs(test.syscalls.ioctlRequests, test.wantRequests) {
				t.Fatalf("ioctl requests = %#x, want %#x", test.syscalls.ioctlRequests, test.wantRequests)
			}
			if !equalInts(test.syscalls.closedFDs, test.wantClosed) {
				t.Fatalf("closed FDs = %v, want %v", test.syscalls.closedFDs, test.wantClosed)
			}
		})
	}
}

func equalUintptrs(left, right []uintptr) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestCasimirFaultAliasIsSharedAndSeparateFromPrivateOverlay(t *testing.T) {
	pageSize := os.Getpagesize()
	base, err := os.CreateTemp("", "casimir-fault-alias-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(base.Name())
	defer base.Close()
	if err := base.Truncate(int64(pageSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := base.WriteAt([]byte{0x11}, 0); err != nil {
		t.Fatal(err)
	}
	private, err := unix.Mmap(
		int(base.Fd()),
		0,
		pageSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(private)
	private[0] = 0x22

	aliasStart, err := mapCasimirFaultAlias(base, uint64(pageSize))
	if err != nil {
		t.Fatalf("mapCasimirFaultAlias() error = %v", err)
	}
	defer unix.Syscall(unix.SYS_MUNMAP, aliasStart, uintptr(pageSize), 0)
	alias := unsafe.Slice((*byte)(unsafe.Pointer(aliasStart)), pageSize)
	if got := alias[0]; got != 0x11 {
		t.Fatalf("shared alias byte = %#x, want backing byte 0x11 instead of private overlay byte 0x22", got)
	}
	if _, err := base.WriteAt([]byte{0x33}, 0); err != nil {
		t.Fatal(err)
	}
	if got := alias[0]; got != 0x33 {
		t.Fatalf("shared alias did not observe backing publication: got %#x, want 0x33", got)
	}
	if got := private[0]; got != 0x22 {
		t.Fatalf("private overlay lost COW byte: got %#x, want 0x22", got)
	}
}

func TestCasimirFaultAliasOneShotRetiresWritableCapability(t *testing.T) {
	pageSize := os.Getpagesize()
	base, err := os.CreateTemp("", "casimir-fault-one-shot-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(base.Name())
	defer base.Close()
	if err := base.Truncate(int64(pageSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := base.WriteAt([]byte("canonical"), 0); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(base.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := verifyCasimirFaultBaseIdentity(readOnly, base); err != nil {
		t.Fatalf("verify one-shot fault base: %v", err)
	}
	before := hashFileAt(t, readOnly, pageSize)

	aliasStart, err := mapCasimirFaultAliasOneShot(base, uint64(pageSize))
	if err != nil {
		t.Fatalf("map one-shot fault alias: %v", err)
	}
	defer unix.Syscall(unix.SYS_MUNMAP, aliasStart, uintptr(pageSize), 0)
	if _, err := base.Stat(); err == nil {
		t.Fatal("one-shot writable base descriptor remained open after mmap")
	}
	if perms := mappingPermissions(t, aliasStart); perms != "r--s" {
		t.Fatalf("fault alias permissions = %q, want read-only shared r--s", perms)
	}
	after := hashFileAt(t, readOnly, pageSize)
	if before != after {
		t.Fatalf("read-only shared alias changed canonical backing bytes")
	}
}

func TestCasimirFaultBaseCapabilitiesFailClosed(t *testing.T) {
	left, err := os.CreateTemp("", "casimir-fault-left-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(left.Name())
	defer left.Close()
	right, err := os.CreateTemp("", "casimir-fault-right-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(right.Name())
	defer right.Close()

	if err := verifyCasimirFaultBaseIdentity(left, right); err == nil {
		t.Fatal("different base files were accepted as one identity")
	}
	readOnly, err := os.Open(left.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := verifyCasimirFaultBaseIdentity(readOnly, readOnly); err == nil {
		t.Fatal("read-only descriptor was accepted as writable one-shot capability")
	}
}

func TestCasimirFaultAliasVMAMayWriteRegistration(t *testing.T) {
	pageSize := os.Getpagesize()
	rawFD, err := unix.MemfdCreate("casimir-vm-maywrite", unix.MFD_CLOEXEC)
	if err != nil {
		t.Skipf("memfd unavailable: %v", err)
	}
	base := os.NewFile(uintptr(rawFD), "casimir-vm-maywrite")
	defer base.Close()
	if err := base.Truncate(int64(pageSize)); err != nil {
		t.Fatal(err)
	}
	fdPath := fmt.Sprintf("/proc/self/fd/%d", rawFD)
	readOnlyFD, err := unix.Open(fdPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	readOnly := os.NewFile(uintptr(readOnlyFD), "casimir-vm-maywrite-ro")
	defer readOnly.Close()
	readWriteFD, err := unix.Open(fdPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	readWrite := os.NewFile(uintptr(readWriteFD), "casimir-vm-maywrite-rw")
	defer readWrite.Close()

	readOnlyStart, err := mapCasimirFaultAlias(readOnly, uint64(pageSize))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Syscall(unix.SYS_MUNMAP, readOnlyStart, uintptr(pageSize), 0)
	if err := registerKernelCasimirFaultRange(readOnlyStart, uint64(pageSize)); err == nil || !errors.Is(err, unix.EPERM) {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) {
			t.Skipf("kernel userfaultfd shmem-minor support unavailable: %v", err)
		}
		t.Fatalf("O_RDONLY PROT_READ|MAP_SHARED registration error = %v, want EPERM", err)
	}

	readWriteStart, err := mapCasimirFaultAlias(readWrite, uint64(pageSize))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Syscall(unix.SYS_MUNMAP, readWriteStart, uintptr(pageSize), 0)
	if perms := mappingPermissions(t, readWriteStart); perms != "r--s" {
		t.Fatalf("corrected fault alias permissions = %q, want r--s", perms)
	}
	if err := registerKernelCasimirFaultRange(readWriteStart, uint64(pageSize)); err != nil {
		t.Fatalf("O_RDWR PROT_READ|MAP_SHARED registration: %v", err)
	}
}

func registerKernelCasimirFaultRange(start uintptr, length uint64) error {
	syscalls := linuxCasimirFaultSyscalls{}
	fd, err := syscalls.userfaultfd(uintptr(unix.O_CLOEXEC | unix.O_NONBLOCK | uffdUserModeOnly))
	if err != nil {
		return err
	}
	defer syscalls.close(int(fd))
	api := uffdioAPIRequest{API: uffdAPI, Features: uffdFeatureMissingShmem | uffdFeatureMinorShmem}
	if err := syscalls.ioctl(fd, uffdioAPI, uintptr(unsafe.Pointer(&api))); err != nil {
		return err
	}
	if api.Features&uffdFeatureMissingShmem == 0 || api.Features&uffdFeatureMinorShmem == 0 {
		return unix.ENOTSUP
	}
	registration := uffdioRegisterRequest{
		Range: uffdioRange{Start: uint64(start), Len: length},
		Mode:  uffdioRegisterMissing | uffdioRegisterMinor,
	}
	return syscalls.ioctl(fd, uffdioRegister, uintptr(unsafe.Pointer(&registration)))
}

func mappingPermissions(t *testing.T, address uintptr) string {
	t.Helper()
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		var start, end uintptr
		var permissions string
		if _, err := fmt.Sscanf(line, "%x-%x %4s", &start, &end, &permissions); err == nil &&
			address >= start && address < end {
			return permissions
		}
	}
	t.Fatalf("no mapping contains address %#x", address)
	return ""
}

func hashFileAt(t *testing.T, file *os.File, size int) [sha256.Size]byte {
	t.Helper()
	buf := make([]byte, size)
	if _, err := file.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(buf)
}

func TestCasimirPrefetchIgnoresMemoryFileTailOutsideSharedBase(t *testing.T) {
	pageSize := uint64(os.Getpagesize())
	mf := &MemoryFile{
		casimirFaultMapping:    1,
		casimirFaultMappingLen: pageSize,
	}
	mf.casimirFaults.Store(1)
	if err := mf.prefetchCasimirRange(memmap.FileRange{Start: pageSize, End: 2 * pageSize}); err != nil {
		t.Fatalf("prefetchCasimirRange(non-base tail) error = %v", err)
	}
}

func (w *recordingCasimirWakeup) continueFault(pageStart, pageSize uint64) error {
	w.calls = append(w.calls, "continue")
	w.pageStart, w.pageSize = pageStart, pageSize
	return nil
}

func (w *recordingCasimirWakeup) zeroFault(pageStart, pageSize uint64) error {
	w.calls = append(w.calls, "zero")
	w.pageStart, w.pageSize = pageStart, pageSize
	return nil
}

func (w *recordingCasimirWakeup) copyFault(pageStart, pageSize uint64, data []byte) error {
	w.calls = append(w.calls, "copy")
	w.pageStart, w.pageSize = pageStart, pageSize
	w.data = append([]byte(nil), data...)
	return nil
}

func TestResolveCasimirFaultUsesExplicitActionAsSoleWakeupAuthority(t *testing.T) {
	pageSize := uint64(4096)
	tests := []struct {
		name     string
		mode     string
		response casimirFaultResponse
		want     string
	}{
		{
			name: "copy",
			mode: "missing",
			response: casimirFaultResponse{
				FaultAction: "copy",
				Data:        bytes.Repeat([]byte{0x5a}, int(pageSize)),
			},
			want: "copy",
		},
		{
			name: "continue",
			mode: "minor",
			response: casimirFaultResponse{
				FaultAction: "continue",
			},
			want: "continue",
		},
		{
			name: "continue after missing publication",
			mode: "missing",
			response: casimirFaultResponse{
				FaultAction: "continue",
			},
			want: "continue",
		},
		{
			name: "zero",
			mode: "missing",
			response: casimirFaultResponse{
				FaultAction: "zero",
			},
			want: "zero",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, wakeup, err := exchangeCasimirFault(t, test.mode, test.response)
			if err != nil {
				t.Fatalf("resolveCasimirFault() error = %v", err)
			}
			if request.Operation != "fault" || request.FaultMode != test.mode ||
				request.Offset != 4096 || request.Length != pageSize {
				t.Fatalf("wire request = %+v, want explicit %q fault mode and exact range", request, test.mode)
			}
			if len(wakeup.calls) != 1 || wakeup.calls[0] != test.want {
				t.Fatalf("wakeup calls = %v, want only %q from explicit action", wakeup.calls, test.want)
			}
			if wakeup.pageStart != 0x12000 || wakeup.pageSize != pageSize {
				t.Fatalf("wakeup range = (%#x, %d), want (%#x, %d)", wakeup.pageStart, wakeup.pageSize, uint64(0x12000), pageSize)
			}
			if test.want == "copy" && !bytes.Equal(wakeup.data, test.response.Data) {
				t.Fatal("copy wakeup did not receive exact verified response bytes")
			}
		})
	}
}

func TestResolveCasimirFaultRejectsWithoutWakeup(t *testing.T) {
	page := bytes.Repeat([]byte{0x5a}, 4096)
	tests := []struct {
		name     string
		mode     string
		response casimirFaultResponse
	}{
		{name: "missing action", mode: "missing", response: casimirFaultResponse{Data: page}},
		{name: "unknown action", mode: "missing", response: casimirFaultResponse{FaultAction: "wake", Data: page}},
		{name: "fatal", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed"}},
		{name: "fatal without error", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true}},
		{name: "fatal with data", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed", Data: page}},
		{name: "copy error", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Error: "verification failed", Data: page}},
		{name: "copy fatal", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Fatal: true, Data: page}},
		{name: "copy continue", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Continue: true, Data: page}},
		{name: "copy zero", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Zero: true, Data: page}},
		{name: "copy without data", mode: "missing", response: casimirFaultResponse{FaultAction: "copy"}},
		{name: "copy short data", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Data: page[:4095]}},
		{name: "copy for minor", mode: "minor", response: casimirFaultResponse{FaultAction: "copy", Data: page}},
		{name: "continue with error", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Error: "verification failed"}},
		{name: "continue with fatal", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Fatal: true}},
		{name: "continue with data", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Continue: true, Data: page}},
		{name: "continue with zero", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Continue: true, Zero: true}},
		{name: "zero for minor", mode: "minor", response: casimirFaultResponse{FaultAction: "zero", Zero: true}},
		{name: "zero with error", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Error: "verification failed"}},
		{name: "zero with fatal", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Fatal: true}},
		{name: "zero with data", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Zero: true, Data: page}},
		{name: "zero with continue", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Zero: true, Continue: true}},
		{name: "fatal with zero", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed", Zero: true}},
		{name: "fatal with continue", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed", Continue: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, wakeup, err := exchangeCasimirFault(t, test.mode, test.response)
			if err == nil {
				t.Fatal("resolveCasimirFault() error = nil, want fail-closed rejection")
			}
			if request.FaultMode != test.mode {
				t.Fatalf("wire request fault mode = %q, want %q", request.FaultMode, test.mode)
			}
			if len(wakeup.calls) != 0 {
				t.Fatalf("rejected response issued wakeups %v", wakeup.calls)
			}
		})
	}
}

func TestResolveCasimirFaultRejectsMalformedResponseWithoutWakeup(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		var request casimirFaultRequest
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			return
		}
		_, _ = server.Write([]byte("{\"fault_action\":\n"))
	}()
	wakeup := &recordingCasimirWakeup{}
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	if err := resolveCasimirFault(rw, wakeup, "missing", 4096, 0x12345, 4096); err == nil {
		t.Fatal("resolveCasimirFault() error = nil, want malformed-response rejection")
	}
	if len(wakeup.calls) != 0 {
		t.Fatalf("malformed response issued wakeups %v", wakeup.calls)
	}
}

func exchangeCasimirFault(t testing.TB, mode string, response casimirFaultResponse) (casimirFaultRequest, *recordingCasimirWakeup, error) {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	requests := make(chan casimirFaultRequest, 1)
	serverErrors := make(chan error, 1)
	go func() {
		defer server.Close()
		var request casimirFaultRequest
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			serverErrors <- err
			return
		}
		requests <- request
		serverErrors <- json.NewEncoder(server).Encode(response)
	}()
	wakeup := &recordingCasimirWakeup{}
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	err := resolveCasimirFault(rw, wakeup, mode, 4096, 0x12345, 4096)
	request := <-requests
	if serverErr := <-serverErrors; serverErr != nil {
		t.Fatalf("fault response server error = %v", serverErr)
	}
	return request, wakeup, err
}
