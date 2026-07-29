load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "state",
    srcs = [
        "state.go",
        "state_metadata.go",
        "state_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sentry/state/checkpointfiles",
        "//pkg/sentry/state/stateio",
        "//pkg/sentry/time",
        "//pkg/state/statefile",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "state_test",
    size = "small",
    srcs = ["state_test.go"],
    library = ":state",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/state/stateio",
    ],
)
