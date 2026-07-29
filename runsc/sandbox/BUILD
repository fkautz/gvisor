load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sandbox",
    srcs = [
        "network.go",
        "network_unsafe.go",
        "no_xdp.go",
        "runtime_native_checkpoint.go",
        "sandbox.go",
        "xdp.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
        "//test:__subpackages__",
    ],
    embed = [":casimir_base"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/control/client",
        "//pkg/control/server",
        "//pkg/coverage",
        "//pkg/fd",
        "//pkg/hostos",
        "//pkg/log",
        "//pkg/metric:metric_go_proto",
        "//pkg/prometheus",
        "//pkg/sentry/control",
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//pkg/sentry/fsimpl/erofs",
        "//pkg/sentry/platform",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/socket/plugin",
        "//pkg/sentry/state/checkpointfiles",
        "//pkg/state/statefile",
        "//pkg/sync",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/urpc",
        "//pkg/xdp",
        "//runsc/boot",
        "//runsc/boot/procfs",
        "//runsc/cgroup",
        "//runsc/checkpointgofer",
        "//runsc/config",
        "//runsc/console",
        "//runsc/donation",
        "//runsc/hostsettings",
        "//runsc/profile",
        "//runsc/sandbox/bpf",
        "//runsc/specutils",
        "//runsc/starttime",
        "//tools/xdp/cmd",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_cilium_ebpf//:go_default_library",
        "@com_github_cilium_ebpf//link:go_default_library",
        "@com_github_moby_sys_capability//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_library(
    name = "casimir_base",
    srcs = ["casimir_base.go"],
    stateify = False,
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "sandbox_test",
    size = "small",
    srcs = [
        "checkpoint_plane_wiring_test.go",
        "network_test.go",
    ],
    library = ":sandbox",
    deps = [
        "//pkg/sentry/control",
        "//pkg/sentry/state/checkpointfiles",
        "//pkg/state/statefile",
        "//runsc/boot",
        "//runsc/config",
        "//runsc/donation",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "runtime_native_checkpoint_test",
    size = "small",
    srcs = [
        "runtime_native_checkpoint.go",
        "runtime_native_checkpoint_test.go",
    ],
    deps = [
        "//pkg/sentry/state/checkpointfiles",
        "//pkg/state/statefile",
    ],
)

go_test(
    name = "casimir_base_test",
    size = "small",
    srcs = ["casimir_base_test.go"],
    embed = [":casimir_base"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
