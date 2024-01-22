package testdata

import (
	"embed"
)

// Dirty hack to bypass issues with Bazel and filesystem access.

//go:embed policies/**.rego
var Policies embed.FS
