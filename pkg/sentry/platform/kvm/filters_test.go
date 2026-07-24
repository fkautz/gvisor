package kvm

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

func TestCasimirUserfaultfdOperationsAreAllowedByKVMFilter(t *testing.T) {
	rules := (&KVM{}).SeccompInfo().SyscallFilters(precompiledseccomp.Values{})
	userfaultfdRule, ok := rules.Get(unix.SYS_USERFAULTFD).(seccomp.PerArg)
	if !ok {
		t.Fatalf("userfaultfd rule = %T, want PerArg", rules.Get(unix.SYS_USERFAULTFD))
	}
	if flags, ok := userfaultfdRule[0].(seccomp.EqualTo); !ok || uintptr(flags) != casimirUserfaultfdFlags {
		t.Fatalf("userfaultfd flags rule = %T %v, want EqualTo(%#x)", userfaultfdRule[0], userfaultfdRule[0], casimirUserfaultfdFlags)
	}

	var userfaultfdAllowed bool
	var continueAllowed bool
	for _, testCase := range rules.UsefulTestCases() {
		if testCase.Nr == int32(unix.SYS_USERFAULTFD) && testCase.Args[0] == casimirUserfaultfdFlags {
			userfaultfdAllowed = true
		}
		if testCase.Nr == int32(unix.SYS_IOCTL) && testCase.Args[1] == uffdioContinue {
			continueAllowed = true
		}
	}
	if !userfaultfdAllowed {
		t.Fatalf("KVM syscall rules do not include userfaultfd flags %#x", casimirUserfaultfdFlags)
	}
	if !continueAllowed {
		t.Fatalf("KVM ioctl rules do not include UFFDIO_CONTINUE %#x", uffdioContinue)
	}
}
