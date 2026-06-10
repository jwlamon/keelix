// Command keelix is the Keelix CLI: a pre-deployment security gate
// for self-hosted Docker Compose stacks.
package main

import (
	"os"

	"github.com/jakelamon/keelix/internal/cli"

	// Blank-import the check aggregator so every check registers itself.
	_ "github.com/jakelamon/keelix/internal/checks/all"
)

func main() {
	os.Exit(cli.Execute())
}
