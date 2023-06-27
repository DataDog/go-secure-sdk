// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/golang/gddo/gosrc"
	"github.com/posener/goreadme"
)

var mdLinkMatcher = regexp.MustCompile(`\[(.*)\]\(/(.*)\)`)

func main() {
	root := os.DirFS(".")

	var paths []string
	// Browse current directory to extract all location to generate the README.md
	fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		// Quit on error
		if err != nil {
			return err
		}

		if !d.IsDir() {
			// Skip files
			return nil
		}

		// Skip invalid directories
		switch d.Name() {
		case "vendor",
			"internal",
			"testdata",
			"mock",
			"tools",
			"test":
			return fs.SkipDir
		default:
		}

		// Ignore if start with a dot
		if d.Name() != "." && strings.HasPrefix(d.Name(), ".") {
			return fs.SkipDir
		}

		// Add to path
		paths = append(paths, path)

		return nil
	})

	ctx := context.Background()

	rootPath, err := filepath.Abs(".")
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range paths {
		// Compute absolute path
		path, err := filepath.Abs(filepath.Join(rootPath, p))
		if err != nil {
			log.Fatal(err)
		}
		gosrc.SetLocalDevMode(path)

		// Generate readme from all paths
		gr := goreadme.New(http.DefaultClient)

		// Create output file
		out, err := os.Create(filepath.Join(path, "README.md"))
		if err != nil {
			log.Fatalf("Failed opening file %s: %s", path, err)
		}
		defer out.Close()

		// Prepare relative package name
		pkg := "."
		if p != "." {
			pkg = "./" + p
		}

		var md bytes.Buffer
		if err := gr.WithConfig(goreadme.Config{
			Consts:               true,
			Vars:                 true,
			Functions:            true,
			Types:                true,
			Factories:            true,
			Methods:              true,
			Credit:               false,
			SkipExamples:         false,
			SkipSubPackages:      false,
			RecursiveSubPackages: p == ".",
			NoDiffBlocks:         true,
		}).Create(ctx, pkg, &md); err != nil {
			panic(err)
		}

		// Patch all urls
		content := md.String()
		content = mdLinkMatcher.ReplaceAllString(content, `[${1}](${2})`)

		// Write to file
		fmt.Fprintln(out, content)
	}
}
