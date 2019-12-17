load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "imgfs",
    srcs = [
        "device.go",
        "file.go",
        "fs.go",
        "inode.go",
        "util.go",
        "util_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/imgfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/refs",
        "//pkg/secio",
        "//pkg/filter",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket/control",

        "//pkg/sentry/unimpl",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/unet",
        "//pkg/waiter",
    ],
)
