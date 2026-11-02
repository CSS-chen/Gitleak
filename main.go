// Command gitleak is a fast .git exposure scanner and repository dumper.
package main

import (
	"os"

	"gitleak/internal/cli"
)

func main() { os.Exit(cli.Run(os.Args[1:])) }
