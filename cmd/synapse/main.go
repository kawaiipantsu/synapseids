// Command synapse is the SynapseIDS administrative CLI. It holds no business
// logic of its own — every verb talks to a running synapsed over its HTTP API
// (PROJECT.md §5.2).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/version"
)

func main() { os.Exit(run(os.Args[1:])) }

const usage = `synapse — SynapseIDS admin CLI (talks to a running synapsed)

Usage:
  synapse [--server URL] <command>

Commands:
  status                        daemon status
  models                        loaded models
  flows [--limit N]             recent flows
  classifications [--limit N]   recent classifications
  replay <file.pcap> [--speed S]   start a PCAP replay (S: 0.5|1|2|10|max)
  replay-stop                   stop the running replay
  version                       print CLI build metadata

Environment:
  SYNAPSE_SERVER   default --server (else http://127.0.0.1:8080)
`

func run(args []string) int {
	fs := flag.NewFlagSet("synapse", flag.ContinueOnError)
	server := fs.String("server", envOr("SYNAPSE_SERVER", "http://127.0.0.1:8080"), "synapsed base URL")
	limit := fs.Int("limit", 20, "row limit for list commands")
	speed := fs.String("speed", "1", "replay speed: 0.5, 1, 2, 10, or max")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	// Go's flag package stops at the first non-flag token, so split the command
	// word out and parse the flags on either side of it. This lets flags come
	// before or after the subcommand: `synapse classifications --limit 50` and
	// `synapse --limit 50 classifications` both work.
	cmd, rest, err := splitCommand(fs, args)
	if err != nil {
		return 2
	}
	if cmd == "" {
		fs.Usage()
		return 2
	}

	c := &client{base: strings.TrimRight(*server, "/")}
	switch cmd {
	case "version", "--version", "-V":
		fmt.Println(version.String("synapse"))
		return 0
	case "help", "--help", "-h":
		fs.Usage()
		return 0
	case "status":
		return c.getPretty("/api/v1/status")
	case "models":
		return c.getPretty("/api/v1/models")
	case "flows":
		return c.getPretty(fmt.Sprintf("/api/v1/flows?limit=%d", *limit))
	case "classifications":
		return c.classifications(*limit)
	case "replay":
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "synapse: replay needs a .pcap path")
			return 2
		}
		return c.replay(rest[0], *speed)
	case "replay-stop":
		return c.post("/api/v1/replay/stop", nil)
	default:
		fmt.Fprintf(os.Stderr, "synapse: unknown command %q\n", cmd)
		fs.Usage()
		return 2
	}
}

// splitCommand parses fs's flags interspersed with positional arguments — Go's
// flag package stops at the first bare word, so this repeatedly parses, peels
// off one positional, and parses again. The first positional is returned as the
// subcommand; `synapse --limit 5 classifications`, `synapse classifications
// --limit 5` and `synapse replay f.pcap --speed max` all work.
func splitCommand(fs *flag.FlagSet, args []string) (cmd string, positional []string, err error) {
	remaining := args
	for {
		if err = fs.Parse(remaining); err != nil {
			return "", nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return cmd, positional, nil
		}
		if cmd == "" {
			cmd = rest[0]
		} else {
			positional = append(positional, rest[0])
		}
		remaining = rest[1:]
	}
}

type client struct{ base string }

func (c *client) do(method, path string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode, nil
}

func (c *client) getPretty(path string) int {
	b, code, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "synapse: %v\n", err)
		return 1
	}
	if code >= 300 {
		fmt.Fprintf(os.Stderr, "synapse: %s: HTTP %d: %s\n", path, code, strings.TrimSpace(string(b)))
		return 1
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		out, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Println(string(b))
	}
	return 0
}

func (c *client) post(path string, body []byte) int {
	b, code, err := c.do(http.MethodPost, path, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "synapse: %v\n", err)
		return 1
	}
	if code >= 300 {
		fmt.Fprintf(os.Stderr, "synapse: HTTP %d: %s\n", code, strings.TrimSpace(string(b)))
		return 1
	}
	fmt.Println(strings.TrimSpace(string(b)))
	return 0
}

func (c *client) replay(path, speed string) int {
	if _, err := capture.ParseSpeed(speed); err != nil {
		fmt.Fprintf(os.Stderr, "synapse: %v\n", err)
		return 2
	}
	abs := path
	if p, err := absPath(path); err == nil {
		abs = p
	}
	body, _ := json.Marshal(map[string]string{"path": abs, "speed": speed})
	return c.post("/api/v1/replay", body)
}

// classifications prints a compact rolling-log-style table.
func (c *client) classifications(limit int) int {
	b, code, err := c.do(http.MethodGet, fmt.Sprintf("/api/v1/classifications?limit=%d", limit), nil)
	if err != nil || code >= 300 {
		fmt.Fprintf(os.Stderr, "synapse: classifications: %v (HTTP %d)\n", err, code)
		return 1
	}
	var rows []struct {
		TS            time.Time `json:"ts"`
		Sensor        string    `json:"sensor"`
		Proto         string    `json:"proto"`
		InitiatorIP   string    `json:"initiator_ip"`
		InitiatorPort int       `json:"initiator_port"`
		ResponderIP   string    `json:"responder_ip"`
		ResponderPort int       `json:"responder_port"`
		Result        struct {
			Class        string  `json:"class"`
			Score        float64 `json:"score"`
			Disagreement bool    `json:"disagreement"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		fmt.Fprintf(os.Stderr, "synapse: %v\n", err)
		return 1
	}
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		flag := " "
		if r.Result.Disagreement {
			flag = "!"
		}
		fmt.Printf("%s %s %-5s %s %21s -> %-21s %-11s %5.1f%%\n",
			flag, r.TS.UTC().Format("15:04:05.000"), r.Proto, pad(r.Sensor, 6),
			fmt.Sprintf("%s:%d", r.InitiatorIP, r.InitiatorPort),
			fmt.Sprintf("%s:%d", r.ResponderIP, r.ResponderPort),
			strings.ToUpper(r.Result.Class), r.Result.Score*100)
	}
	return 0
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func absPath(p string) (string, error) {
	if strings.HasPrefix(p, "/") {
		return p, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return wd + "/" + p, nil
}
