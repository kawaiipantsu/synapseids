package capture

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// SSHConfig configures an authorized remote tcpdump capture over SSH (issue
// #30, PROJECT.md §6 "SSH remote tcpdump").
type SSHConfig struct {
	// SSHBinary is the ssh client to run. "" => "ssh".
	SSHBinary string
	// Destination is "user@host" or an ssh_config Host alias. Required.
	Destination string
	// Port is the SSH port. 0 => ssh's default (or whatever ssh_config sets).
	Port int
	// IdentityFile is an optional private-key path (ssh -i).
	IdentityFile string
	// RemoteBinary is the tcpdump-compatible program on the far side. "" =>
	// "tcpdump".
	RemoteBinary string
	// Interface is the remote interface to capture on. Required.
	Interface string
	// Filter is a real tcpdump filter expression, tokenised and each token
	// shell-quoted for the remote shell (never concatenated raw — §28.18).
	Filter string
	// Snaplen is the remote tcpdump -s. 0 keeps tcpdump's default.
	Snaplen int
	// ExtraSSHArgs are inserted verbatim before the destination.
	ExtraSSHArgs []string
	// KnownHostsMode is "strict" (default; ssh StrictHostKeyChecking=yes) or
	// "accept-new" (trust-on-first-use). "no" is deliberately not offered.
	KnownHostsMode string
	// Authorized must be explicitly true: the operator asserts they are
	// authorised to monitor Destination (§28.18, PROJECT.md §21).
	Authorized bool
}

// SSHtcpdump argv assembly: the ssh options we always set. BatchMode=yes means
// ssh never blocks on an interactive password/passphrase prompt — a key-only
// host fails fast instead of hanging the daemon.
const (
	sshStrictYes       = "StrictHostKeyChecking=yes"
	sshStrictAcceptNew = "StrictHostKeyChecking=accept-new"
)

// SSHTcpdump runs `ssh <opts> <dest> tcpdump -U -w - ...` and decodes the
// remote tcpdump's stdout through the same shared engine as TcpdumpStream. Only
// the argv differs; the subprocess lifecycle is identical (pcapSubprocess).
type SSHTcpdump struct {
	*pcapSubprocess
	destination string
	iface       string
	filter      string
	remoteCmd   string
}

// NewSSHTcpdump validates the config, enforces the §28.18 authorization gate,
// resolves the ssh binary and assembles the argv. It does not connect; Packets
// does.
func NewSSHTcpdump(cfg SSHConfig) (*SSHTcpdump, error) {
	if cfg.Destination == "" {
		return nil, errors.New("ssh: destination is required (\"user@host\" or an ssh_config alias)")
	}
	if cfg.Interface == "" {
		return nil, errors.New("ssh: interface is required")
	}
	if !cfg.Authorized {
		return nil, fmt.Errorf("ssh: remote capture requires \"authorized\": true — you must be authorised to monitor %s (PROJECT.md §28.18)", cfg.Destination)
	}
	if cfg.Snaplen < 0 || cfg.Snaplen > maxSnapLen {
		return nil, fmt.Errorf("ssh: snaplen %d out of range [0,%d]", cfg.Snaplen, maxSnapLen)
	}

	strict, err := sshStrictOption(cfg.KnownHostsMode)
	if err != nil {
		return nil, err
	}

	bin := cfg.SSHBinary
	if bin == "" {
		bin = "ssh"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("ssh: %q not found on PATH: %w", bin, err)
	}

	remoteBin := cfg.RemoteBinary
	if remoteBin == "" {
		remoteBin = "tcpdump"
	}
	remoteCmd := remoteTcpdumpCommand(remoteBin, cfg.Interface, cfg.Filter, cfg.Snaplen)
	args := sshArgs(cfg, strict, remoteCmd)

	return &SSHTcpdump{
		pcapSubprocess: newPCAPSubprocess("ssh", path, args),
		destination:    cfg.Destination,
		iface:          cfg.Interface,
		filter:         cfg.Filter,
		remoteCmd:      remoteCmd,
	}, nil
}

// Destination reports the ssh target.
func (s *SSHTcpdump) Destination() string { return s.destination }

// Interface reports the remote interface being captured.
func (s *SSHTcpdump) Interface() string { return s.iface }

// Filter reports the raw tcpdump filter expression.
func (s *SSHTcpdump) Filter() string { return s.filter }

// RemoteCommand reports the exact (shell-quoted) command string handed to ssh.
func (s *SSHTcpdump) RemoteCommand() string { return s.remoteCmd }

// Argv returns a copy of the exact ssh command line that will be executed.
func (s *SSHTcpdump) Argv() []string { return append([]string(nil), s.argv...) }

func sshStrictOption(mode string) (string, error) {
	switch mode {
	case "", "strict":
		return sshStrictYes, nil
	case "accept-new":
		return sshStrictAcceptNew, nil
	default:
		return "", fmt.Errorf("ssh: known_hosts mode %q is not one of \"strict\", \"accept-new\"", mode)
	}
}

// sshArgs builds:
//
//	[-p PORT] [-i IDENTITY] -o BatchMode=yes -o StrictHostKeyChecking=<mode> [extra...] DEST REMOTE-CMD
func sshArgs(cfg SSHConfig, strict, remoteCmd string) []string {
	var a []string
	if cfg.Port != 0 {
		a = append(a, "-p", strconv.Itoa(cfg.Port))
	}
	if cfg.IdentityFile != "" {
		a = append(a, "-i", cfg.IdentityFile)
	}
	a = append(a, "-o", "BatchMode=yes", "-o", strict)
	a = append(a, cfg.ExtraSSHArgs...)
	a = append(a, cfg.Destination, remoteCmd)
	return a
}

// remoteTcpdumpCommand assembles the fixed remote command
//
//	<bin> -U -w - -i <iface> -s <snaplen> <filter tokens...>
//
// as one string for ssh to hand to the remote login shell. Every
// operator-influenced field is shell-quoted so a crafted interface name or
// filter token cannot break out of the command (§28.18).
func remoteTcpdumpCommand(bin, iface, filter string, snaplen int) string {
	parts := []string{
		shQuote(bin),
		"-U", "-w", "-",
		"-i", shQuote(iface),
		"-s", strconv.Itoa(snaplen),
	}
	for _, tok := range strings.Fields(filter) {
		parts = append(parts, shQuote(tok))
	}
	return strings.Join(parts, " ")
}

// shQuote returns s quoted for a POSIX shell. Unquoted when s contains only
// characters that are always literal; otherwise single-quoted with embedded
// single quotes rendered as '\”.
func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	if shSafe(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case strings.ContainsRune("_@%+=:,./-", r):
		default:
			return false
		}
	}
	return true
}
