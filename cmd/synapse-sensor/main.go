// Command synapse-sensor is a placeholder for the distributed lightweight
// capture agent described in PROJECT.md §5.3. The full sensor — raw / flow /
// feature modes, reconnect, location identity — arrives in Phase 6.
//
// It already ships one working transport: the "pcap-over-ip" subcommand serves
// the SYNPOIP protocol (internal/capture/pcapoverip) over TLS, replaying a
// capture file to a connecting synapsed. That makes issue #31 demoable end to
// end and is the seam the Phase 6 sensor will grow from.
package main

import (
	"fmt"
	"os"

	"github.com/kawaiipantsu/synapseids/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) >= 1 && args[0] == "pcap-over-ip" {
		os.Exit(runPCAPOverIP(args[1:]))
	}
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version" || args[0] == "-V") {
		fmt.Println(version.String("synapse-sensor"))
		return
	}
	fmt.Fprintln(os.Stderr, "synapse-sensor: only the pcap-over-ip transport is implemented so far.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --listen :4789 --token-file tok --from capture.pcap")
	fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --help")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Distributed remote capture (raw / flow / feature modes, reconnect, sensor")
	fmt.Fprintln(os.Stderr, "identity) is Phase 6 — see PROJECT.md §5.3 and the EPIC: Phase 6 issues.")
	os.Exit(1)
}
