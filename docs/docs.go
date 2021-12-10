package main

import (
	"github.com/spf13/cobra/doc"
	"gitlab.com/testifysec/witness/cmd"
)

func main() {
	// Generate CLI docs
	witness := cmd.GetCommand()
	doc.GenMarkdownTreeCustom(witness, ".", func(s string) string { return s }, func(s string) string { return s })

}
