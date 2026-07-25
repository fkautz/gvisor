package kvm

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
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

	requiredIOCTLs := map[uint64]bool{
		uffdioAPI:      false,
		uffdioRegister: false,
		uffdioCopy:     false,
		uffdioZeropage: false,
		uffdioContinue: false,
	}
	var userfaultfdAllowed bool
	for _, testCase := range rules.UsefulTestCases() {
		if testCase.Nr == int32(unix.SYS_USERFAULTFD) && testCase.Args[0] == casimirUserfaultfdFlags {
			userfaultfdAllowed = true
		}
		if testCase.Nr == int32(unix.SYS_IOCTL) {
			if _, required := requiredIOCTLs[testCase.Args[1]]; required {
				requiredIOCTLs[testCase.Args[1]] = true
			}
		}
	}
	if !userfaultfdAllowed {
		t.Fatalf("KVM syscall rules do not include userfaultfd flags %#x", casimirUserfaultfdFlags)
	}
	for request, allowed := range requiredIOCTLs {
		if !allowed {
			t.Errorf("KVM ioctl rules do not include required userfaultfd request %#x", request)
		}
	}
}

func TestCasimirUserfaultfdPolicyMatchesPrecompiledBPF(t *testing.T) {
	info := (&KVM{}).SeccompInfo()
	rules := info.SyscallFilters(precompiledseccomp.Values{})
	program := func() *seccomp.Program {
		return &seccomp.Program{
			RuleSets: []seccomp.RuleSet{{Rules: rules.Copy(), Action: seccomp.Allow}},
			Options:  seccomp.ProgramOptions{HotSyscalls: info.HottestSyscalls()},
		}
	}
	dynamicInstructions, _, err := program().Build()
	if err != nil {
		t.Fatalf("building non-precompiled KVM policy: %v", err)
	}
	precompiled, err := precompiledseccomp.Precompile("kvm-casimir-userfaultfd", nil, func(precompiledseccomp.Values) *seccomp.Program {
		return program()
	})
	if err != nil {
		t.Fatalf("precompiling KVM policy: %v", err)
	}
	precompiledInstructions, err := precompiled.RenderInstructions(precompiledseccomp.Values{})
	if err != nil {
		t.Fatalf("rendering precompiled KVM policy: %v", err)
	}

	tests := []struct {
		name        string
		data        linux.SeccompData
		wantAllowed bool
	}{
		{
			name: "userfaultfd exact flags",
			data: linux.SeccompData{
				Nr:   int32(unix.SYS_USERFAULTFD),
				Arch: seccomp.LINUX_AUDIT_ARCH,
				Args: [6]uint64{casimirUserfaultfdFlags},
			},
			wantAllowed: true,
		},
		{
			name: "userfaultfd extra flags rejected",
			data: linux.SeccompData{
				Nr:   int32(unix.SYS_USERFAULTFD),
				Arch: seccomp.LINUX_AUDIT_ARCH,
				Args: [6]uint64{casimirUserfaultfdFlags | 2},
			},
		},
	}
	for _, request := range []uint64{uffdioAPI, uffdioRegister, uffdioCopy, uffdioZeropage, uffdioContinue} {
		tests = append(tests, struct {
			name        string
			data        linux.SeccompData
			wantAllowed bool
		}{
			name: fmt.Sprintf("userfaultfd ioctl %#x", request),
			data: linux.SeccompData{
				Nr:   int32(unix.SYS_IOCTL),
				Arch: seccomp.LINUX_AUDIT_ARCH,
				Args: [6]uint64{9, request},
			},
			wantAllowed: true,
		})
	}
	tests = append(tests,
		struct {
			name        string
			data        linux.SeccompData
			wantAllowed bool
		}{
			name: "unrelated ioctl rejected",
			data: linux.SeccompData{
				Nr:   int32(unix.SYS_IOCTL),
				Arch: seccomp.LINUX_AUDIT_ARCH,
				Args: [6]uint64{9, 0xc020aa01},
			},
		},
		struct {
			name        string
			data        linux.SeccompData
			wantAllowed bool
		}{
			name: "negative fd rejected",
			data: linux.SeccompData{
				Nr:   int32(unix.SYS_IOCTL),
				Arch: seccomp.LINUX_AUDIT_ARCH,
				Args: [6]uint64{^uint64(0), uffdioRegister},
			},
		},
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dynamicResult := executeKVMPolicy(t, dynamicInstructions, &test.data)
			precompiledResult := executeKVMPolicy(t, precompiledInstructions, &test.data)
			if gotAllowed := dynamicResult == uint32(linux.SECCOMP_RET_ALLOW); gotAllowed != test.wantAllowed {
				t.Errorf("non-precompiled policy allowed = %t, want %t (result %#x)", gotAllowed, test.wantAllowed, dynamicResult)
			}
			if gotAllowed := precompiledResult == uint32(linux.SECCOMP_RET_ALLOW); gotAllowed != test.wantAllowed {
				t.Errorf("precompiled policy allowed = %t, want %t (result %#x)", gotAllowed, test.wantAllowed, precompiledResult)
			}
			if dynamicResult != precompiledResult {
				t.Errorf("non-precompiled result %#x differs from precompiled result %#x", dynamicResult, precompiledResult)
			}
		})
	}
}

func executeKVMPolicy(t testing.TB, instructions []bpf.Instruction, data *linux.SeccompData) uint32 {
	t.Helper()
	program, err := bpf.Compile(instructions, true)
	if err != nil {
		t.Fatalf("compiling KVM policy for interpretation: %v", err)
	}
	buf := make([]byte, data.SizeBytes())
	result, err := bpf.Exec[bpf.NativeEndian](program, seccomp.DataAsBPFInput(data, buf))
	if err != nil {
		t.Fatalf("executing KVM policy: %v", err)
	}
	return result
}
