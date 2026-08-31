package capture

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// TcpdumpConfig configures a local tcpdump-stream capture source (issue #29).
type TcpdumpConfig struct {
	// Binary is the tcpdump-compatible program to run. "" => "tcpdump" (found
	// on $PATH).
	Binary string
	// Interface is the local interface tcpdump listens on (tcpdump -i). Required.
	Interface string
	// Filter is a real tcpdump filter expression ("tcp port 80 or icmp"). It is
	// tokenised on whitespace and passed as trailing argv elements — never a
	// shell string, so it cannot inject a command (§28.18).
	Filter string
	// Snaplen is tcpdump -s. 0 keeps tcpdump's own default (full packet).
	Snaplen int
	// ExtraArgs are inserted verbatim after the fixed options and before the
	// filter tokens (e.g. ["-p"] to disable promiscuous mode).
	ExtraArgs []string
}

// TcpdumpStream is a Source that runs `tcpdump -U --immediate-mode -w -` and
// decodes its stdout through the shared pcap-stream engine, exactly as a PCAP
// file or a live NIC would be decoded (PROJECT.md §6). The subprocess lifecycle
// (process group, kill-on-cancel, stderr capture, reaping) is pcapSubprocess.
type TcpdumpStream struct {
	*pcapSubprocess
	iface  string
	filter string
}

// NewTcpdumpStream resolves the binary and assembles the argv. It does not
// start tcpdump; Packets does.
func NewTcpdumpStream(cfg TcpdumpConfig) (*TcpdumpStream, error) {
	bin := cfg.Binary
	if bin == "" {
		bin = "tcpdump"
	}
	if cfg.Interface == "" {
		return nil, errors.New("tcpdump: interface is required")
	}
	if cfg.Snaplen < 0 || cfg.Snaplen > maxSnapLen {
		return nil, fmt.Errorf("tcpdump: snaplen %d out of range [0,%d]", cfg.Snaplen, maxSnapLen)
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("tcpdump: %q not found on PATH: %w — install tcpdump or set the source's \"binary\"", bin, err)
	}

	args := tcpdumpArgs(cfg.Interface, cfg.Filter, cfg.Snaplen, cfg.ExtraArgs)
	return &TcpdumpStream{
		pcapSubprocess: newPCAPSubprocess("tcpdump", path, args),
		iface:          cfg.Interface,
		filter:         cfg.Filter,
	}, nil
}

// Interface reports the interface tcpdump was told to listen on.
func (t *TcpdumpStream) Interface() string { return t.iface }

// Filter reports the raw tcpdump filter expression ("" = capture everything).
func (t *TcpdumpStream) Filter() string { return t.filter }

// Argv returns a copy of the exact command line that will be executed.
func (t *TcpdumpStream) Argv() []string { return append([]string(nil), t.argv...) }

// tcpdumpArgs builds the fixed tcpdump command line:
//
//	-U --immediate-mode -w - -i <iface> -s <snaplen> [extra...] [filter tokens...]
//
// -U flushes per packet and --immediate-mode delivers frames as they arrive, so
// the pipeline sees live latency rather than tcpdump's output buffering.
func tcpdumpArgs(iface, filter string, snaplen int, extra []string) []string {
	args := []string{
		"-U", "--immediate-mode",
		"-w", "-",
		"-i", iface,
		"-s", strconv.Itoa(snaplen),
	}
	args = append(args, extra...)
	args = append(args, strings.Fields(filter)...)
	return args
}
