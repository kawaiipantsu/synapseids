package capture

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// stderrRingBytes bounds how much of a subprocess's stderr we keep for the
// terminal error message. A few KiB comfortably covers tcpdump's banner plus
// its "N packets dropped by kernel" summary.
const stderrRingBytes = 8 << 10

// pcapSubprocess is the shared engine behind every "run a program whose stdout
// is a classic-pcap (or pcapng) byte stream" capture source: TcpdumpStream
// (issue #29) and SSHTcpdump (issue #30) today, and it will suit PCAP-over-IP's
// helper mode later (ADR 0011).
//
// It owns the child's whole lifecycle: start it in its own process group, pipe
// stdout through decodePCAPStream, keep a bounded tail of stderr, and on
// ctx-cancel / Close kill the group and reap — no zombies, no leaked fds. There
// is no auto-restart; a crash surfaces as a terminal error and the Manager
// flips the source to state "error".
type pcapSubprocess struct {
	st streamStats // first: keep the atomics 8-byte aligned on 386

	label string   // "tcpdump" / "ssh" — the prefix on every error it emits
	argv  []string // argv[0] is the resolved absolute binary path

	started atomic.Bool
	closed  atomic.Bool

	mu     sync.Mutex
	cancel context.CancelFunc
}

// newPCAPSubprocess builds the engine. bin must already be resolved with
// exec.LookPath by the caller so a missing binary is reported at construction
// time with source-specific guidance.
func newPCAPSubprocess(label, bin string, args []string) *pcapSubprocess {
	return &pcapSubprocess{label: label, argv: append([]string{bin}, args...)}
}

// Packets starts the child and streams its decoded packets. The terminal error
// (non-zero exit, spawn failure, malformed stream) lands on the error channel;
// a deliberate Close / ctx-cancel is not an error.
func (p *pcapSubprocess) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	p.started.Store(true)
	out := make(chan packet.Packet, 256)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)
		p.run(ctx, out, errc)
	}()

	return out, errc
}

func (p *pcapSubprocess) run(ctx context.Context, out chan<- packet.Packet, errc chan<- error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p.mu.Lock()
	p.cancel = cancel
	p.mu.Unlock()

	if p.closed.Load() {
		return
	}

	cmd := exec.CommandContext(cctx, p.argv[0], p.argv[1:]...) //nolint:gosec // argv built from a fixed template, never a shell string (§28.18)
	// Own process group so a shell-wrapped remote tcpdump (ssh runs the command
	// through a login shell) dies with us, not just the ssh client.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid = the whole group. Fall back to the bare process.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	// If a grandchild keeps the stdout pipe open after the kill, don't block
	// Wait forever.
	cmd.WaitDelay = 3 * time.Second

	ring := &stderrRing{max: stderrRingBytes}
	cmd.Stderr = ring

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		errc <- fmt.Errorf("%s: stdout pipe: %w", p.label, err)
		return
	}
	if err := cmd.Start(); err != nil {
		errc <- fmt.Errorf("%s: start %q: %w", p.label, p.argv[0], err)
		return
	}

	// decodePCAPStream blocks until stdout hits EOF (child exited or was
	// killed) or ctx is cancelled. Its own terminal error goes to a private
	// channel so we can prefer the process exit status.
	decErrc := make(chan error, 1)
	decodePCAPStream(cctx, stdout, out, decErrc, &p.st)
	var decErr error
	select {
	case decErr = <-decErrc:
	default:
	}

	waitErr := cmd.Wait()

	switch {
	case p.closed.Load() || errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return // deliberate shutdown — not an error
	case exitCodeOf(waitErr) > 0:
		errc <- fmt.Errorf("%s: exit %d: %s", p.label, exitCodeOf(waitErr), ring.tail())
	case waitErr != nil:
		errc <- fmt.Errorf("%s: %v: %s", p.label, waitErr, ring.tail())
	case decErr != nil && !isCancel(decErr):
		errc <- fmt.Errorf("%s: %w", p.label, decErr)
	}
}

// Stats returns the decoder's counter snapshot. Drops stays 0: tcpdump reports
// kernel drops only as a stderr line at exit, which the Manager's live
// per-second sampling can't consume (noted in ADR 0011).
func (p *pcapSubprocess) Stats() Stats { return p.st.snapshot() }

// Close cancels the child (killing its process group) and returns immediately;
// the Packets goroutine reaps it. Safe before Packets and safe to call twice.
func (p *pcapSubprocess) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// exitCodeOf returns the child's exit status, or 0 when err is not an
// *exec.ExitError (a signal kill reports -1 and is handled by the caller's
// generic branch).
func exitCodeOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 0
}

// stderrRing keeps only the last max bytes written to it.
type stderrRing struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (r *stderrRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	return len(p), nil
}

// tail returns the retained stderr, whitespace-trimmed and single-lined so it
// reads cleanly inside a wrapped error.
func (r *stderrRing) tail() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := strings.TrimSpace(string(r.buf))
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "(no stderr)"
	}
	return s
}
