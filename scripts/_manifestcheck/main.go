// Command manifestcheck validates a manifest with the pinned Kandev's own
// manifest package, which is internal to the Kandev module. `make
// validate-manifest` compiles it inside that module through `go run
// -overlay`, so nothing is written into the sibling checkout. The leading
// underscore keeps this directory out of `./...` in this module.
package main

import (
	"fmt"
	"os"

	"github.com/kandev/kandev/internal/plugins/manifest"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: manifestcheck <manifest.yaml>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	parsed, err := manifest.Parse(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	if err := parsed.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "invalid:", err)
		os.Exit(1)
	}
	fmt.Printf("manifest OK: %s %s\n", parsed.ID, parsed.Version)
}
