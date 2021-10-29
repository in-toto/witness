package cmd

import (
	"fmt"
	"os"

	"github.com/gookit/color"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "witness",
	Short: "Collect and verify attestations about your build environments",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}
