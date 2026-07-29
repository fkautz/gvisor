load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "checkpointfiles",
    srcs = ["checkpointfiles.go"],
    visibility = ["//:sandbox"],
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "checkpointfiles_test",
    size = "small",
    srcs = ["checkpointfiles_test.go"],
    library = ":checkpointfiles",
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
