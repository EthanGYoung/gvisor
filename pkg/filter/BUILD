package(licenses = ["notice"])

load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "filter",
    srcs = [
        "filter.go",
        "bloom.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/filter",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "@com_github_spaolacci_murmur3//:go_default_library",
    ],
)
