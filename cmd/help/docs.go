package main

import (
	"github.com/spf13/cobra/doc"
	"github.com/testifysec/witness/cmd"
)

func main() {
	// Generate CLI docs
	doc.GenMarkdownTree(cmd.GetCommand(), "docs")
}
