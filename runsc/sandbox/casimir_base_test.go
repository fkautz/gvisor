package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDuplicateVerifiedInheritedBaseImageCapabilities(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "base.img")
	const content = "canonical-base-content"
	if err := os.WriteFile(basePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	readOnlySource, err := os.Open(basePath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnlySource.Close()
	readOnly, identity, err := duplicateVerifiedInheritedBaseImage(int(readOnlySource.Fd()), unix.O_RDONLY, nil)
	if err != nil {
		t.Fatalf("open read-only base: %v", err)
	}
	defer readOnly.Close()
	assertBaseAccess(t, readOnly, unix.O_RDONLY)

	faultFD, err := unix.Open(basePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	faultBase, faultIdentity, err := consumeVerifiedInheritedFaultBaseImage(faultFD, &identity)
	if err != nil {
		t.Fatalf("open one-shot fault base: %v", err)
	}
	defer faultBase.Close()
	if _, err := unix.FcntlInt(uintptr(faultFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("inherited one-shot fault descriptor remained open: %v", err)
	}
	assertBaseAccess(t, faultBase, unix.O_RDWR)
	if faultIdentity != identity {
		t.Fatalf("fault identity %+v differs from read-only identity %+v", faultIdentity, identity)
	}

	got, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("base content changed during capability acquisition: got %q", got)
	}
}

func TestDuplicateVerifiedInheritedBaseImageFailsClosed(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "base.img")
	if err := os.WriteFile(basePath, []byte("base"), 0600); err != nil {
		t.Fatal(err)
	}
	readOnlySource, err := os.Open(basePath)
	if err != nil {
		t.Fatal(err)
	}
	readOnly, identity, err := duplicateVerifiedInheritedBaseImage(int(readOnlySource.Fd()), unix.O_RDONLY, nil)
	if err != nil {
		t.Fatal(err)
	}
	readOnly.Close()
	defer readOnlySource.Close()

	wrongIdentity := identity
	wrongIdentity.ino++
	readWriteSource, err := os.OpenFile(basePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer readWriteSource.Close()
	if file, _, err := duplicateVerifiedInheritedBaseImage(int(readWriteSource.Fd()), unix.O_RDWR, &wrongIdentity); err == nil {
		file.Close()
		t.Fatal("duplicate succeeded against wrong identity")
	}
	wrongFD, err := unix.Open(basePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if file, _, err := consumeVerifiedInheritedFaultBaseImage(wrongFD, &wrongIdentity); err == nil {
		file.Close()
		t.Fatal("consumed fault base succeeded against wrong identity")
	}
	if _, err := unix.FcntlInt(uintptr(wrongFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("rejected inherited fault descriptor remained open: %v", err)
	}
	if file, _, err := duplicateVerifiedInheritedBaseImage(int(readOnlySource.Fd()), unix.O_WRONLY, nil); err == nil {
		file.Close()
		t.Fatal("write-only base capability was admitted")
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if file, _, err := duplicateVerifiedInheritedBaseImage(int(directory.Fd()), unix.O_RDONLY, nil); err == nil {
		file.Close()
		t.Fatal("directory base image was admitted")
	}
	closed, err := os.Open(basePath)
	if err != nil {
		t.Fatal(err)
	}
	closedFD := int(closed.Fd())
	closed.Close()
	if file, _, err := duplicateVerifiedInheritedBaseImage(closedFD, unix.O_RDONLY, nil); err == nil {
		file.Close()
		t.Fatal("closed inherited base descriptor was admitted")
	}
}

func TestExactInheritedFD(t *testing.T) {
	t.Setenv("CASIMIR_CANONICAL_BACKING_FD", "3")
	if got, err := exactInheritedFD("CASIMIR_CANONICAL_BACKING_FD", 3); err != nil || got != 3 {
		t.Fatalf("exactInheritedFD() = (%d, %v), want (3, nil)", got, err)
	}
	for _, value := range []string{"", "4", "base.img"} {
		t.Setenv("CASIMIR_CANONICAL_BACKING_FD", value)
		if _, err := exactInheritedFD("CASIMIR_CANONICAL_BACKING_FD", 3); err == nil {
			t.Fatalf("inherited descriptor value %q was admitted", value)
		}
	}
}

func assertBaseAccess(t *testing.T, file *os.File, want int) {
	t.Helper()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := flags & unix.O_ACCMODE; got != want {
		t.Fatalf("access flags = %#x, want %#x", got, want)
	}
	fdFlags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("base capability lacks CLOEXEC")
	}
}
