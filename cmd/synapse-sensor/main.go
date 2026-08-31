// Command synapse-sensor is the distributed lightweight capture agent described
// in PROJECT.md §5.3. It captures on a local NIC (or replays a file) and streams
// raw records to a central synapsed over the framed, authenticated SYNPOIP
// transport (internal/capture/pcapoverip).
//
// Two transport postures: `--listen` (the daemon dials the sensor) and
// `--connect` (the sensor dials the daemon's collector — for a sensor behind
// NAT, e.g. an OPNsense firewall on a WAN edge). Sensor identity — id and
// location — travels in the handshake either way. Raw records only for now;
// `flow` / `feature` modes are #45.
package main

import (
	"fmt"
	"os"

	"github.com/kawaiipantsu/synapseids/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) >= 1 {
		switch args[0] {
		case "pcap-over-ip":
			os.Exit(runPCAPOverIP(args[1:]))
		case "gen-cert":
			os.Exit(runGenCert(args[1:]))
		case "doctor", "selftest":
			os.Exit(runDoctor(args[1:]))
		case "version", "--version", "-V":
			fmt.Println(version.String("synapse-sensor"))
			return
		}
	}
	// No subcommand: print the build stamp (issue #43) and a one-line pointer at
	// the transports, then exit 0.
	fmt.Println(version.String("synapse-sensor"))
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --connect ids.example:4789 --token-file tok --sensor-id edge-1 --location wan --iface em0 --authorized")
	fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --listen :4789 --from capture.pcap")
	fmt.Fprintln(os.Stderr, "  synapse-sensor gen-cert --host ids.example --cert collector.crt --key collector.key")
	fmt.Fprintln(os.Stderr, "  synapse-sensor doctor          # selftest a deployed sensor (OPNsense: service synapseids_sensor selftest)")
	fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --help")
}
