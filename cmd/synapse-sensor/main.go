// Command synapse-sensor is a placeholder for the distributed lightweight capture
// agent described in PROJECT.md §5.3. Distributed sensors — authenticated,
// encrypted transport with raw / flow / feature modes — arrive in Phase 6. Until
// then this binary only reports its version so packaging and release tooling can
// treat all three commands uniformly.
package main

import (
	"fmt"
	"os"

	"github.com/kawaiipantsu/synapseids/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version" || args[0] == "-V") {
		fmt.Println(version.String("synapse-sensor"))
		return
	}
	fmt.Fprintln(os.Stderr, "synapse-sensor: not implemented yet.")
	fmt.Fprintln(os.Stderr, "Distributed remote capture (raw / flow / feature modes over an")
	fmt.Fprintln(os.Stderr, "authenticated, encrypted transport) is Phase 6 — see PROJECT.md §5.3")
	fmt.Fprintln(os.Stderr, "and https://github.com/kawaiipantsu/synapseids/issues (EPIC: Phase 6).")
	fmt.Fprintln(os.Stderr, "\nFor now, capture on the daemon host or feed synapsed a PCAP:")
	fmt.Fprintln(os.Stderr, "  synapse replay ./capture.pcap --speed 2")
	os.Exit(1)
}
