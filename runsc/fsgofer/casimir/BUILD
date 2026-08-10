load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "casimir",
    srcs = [
        "bridge.go",
        "lisafs.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/lisafs",
        "//pkg/marshal/primitive",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "casimir_test",
    size = "small",
    srcs = ["bridge_test.go"],
    library = ":casimir",
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
