// Command fakecap is a test stub that stands in for `tcpdump` and `ssh` in the
// internal/capture subprocess tests. It ignores every argument it is given
// (an ssh invocation, a tcpdump invocation — does not matter) and is driven
// entirely by environment variables:
//
//	FAKECAP_ARGV_FILE  if set, write each os.Arg (one per line) here, then continue
//	FAKECAP_STDERR     if set, write this string to stderr
//	FAKECAP_PCAP       if set, copy this file's bytes to stdout
//	FAKECAP_SLEEP_MS   if set, sleep this many milliseconds (simulates a live capture)
//	FAKECAP_EXIT       process exit code (default 0)
//
// It is never part of the module build: `go build ./...` skips testdata/.
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

func main() {
	if f := os.Getenv("FAKECAP_ARGV_FILE"); f != "" {
		data := ""
		for _, a := range os.Args {
			data += a + "\n"
		}
		if err := os.WriteFile(f, []byte(data), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "fakecap: argv file:", err)
			os.Exit(3)
		}
	}

	if s := os.Getenv("FAKECAP_STDERR"); s != "" {
		fmt.Fprint(os.Stderr, s)
	}

	if p := os.Getenv("FAKECAP_PCAP"); p != "" {
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fakecap: open pcap:", err)
			os.Exit(3)
		}
		_, _ = io.Copy(os.Stdout, f)
		_ = f.Close()
	}

	if ms := os.Getenv("FAKECAP_SLEEP_MS"); ms != "" {
		if n, err := strconv.Atoi(ms); err == nil {
			time.Sleep(time.Duration(n) * time.Millisecond)
		}
	}

	code := 0
	if c := os.Getenv("FAKECAP_EXIT"); c != "" {
		if n, err := strconv.Atoi(c); err == nil {
			code = n
		}
	}
	os.Exit(code)
}
