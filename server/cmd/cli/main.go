// edr-cli — Kizashi command-line interface
package main

import (
	"fmt"
	"os"

	"github.com/edr-platform/server/cmd/cli/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
