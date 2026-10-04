// synapse-extract performs bounded OFFLINE PCAP-to-behavior extraction for the
// separate training worker. No packets are transmitted and no services opened.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
)

type row struct {
	Values       [160]float64 `json:"values"`
	Label        string       `json:"label"`
	Group        string       `json:"group"`
	Conversation string       `json:"conversation"`
	Time         float64      `json:"time"`
}
type officialLabel struct {
	start, end time.Time
	label      string
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	file := flag.String("pcap", "", "Offline capture path")
	label := flag.String("label", "", "Explicit analyst label for every flow, or omitted with --ctu-labels")
	official := flag.String("ctu-labels", "", "Official CTU .binetflow labels, matched by oriented tuple and time")
	maxRows := flag.Int("max-rows", 100000, "Maximum emitted flow rows")
	flag.Parse()
	if *file == "" || (*label == "" && *official == "") || *maxRows < 1 || *maxRows > 100000 {
		return errors.New("pcap, valid labels and max-rows 1..100000 required")
	}
	source, e := capture.OpenPCAPFile(*file)
	if e != nil {
		return errors.New("capture cannot be opened")
	}
	defer func() { _ = source.Close() }()
	labels, e := readLabels(*official)
	if e != nil {
		return e
	}
	f, e := os.Open(*file)
	if e != nil {
		return e
	}
	h := sha256.New()
	_, e = io.Copy(h, io.LimitReader(f, 512<<20))
	_ = f.Close()
	if e != nil {
		return e
	}
	digest := hex.EncodeToString(h.Sum(nil))
	records := make([]flow.Record, 0, min(*maxRows, 20000))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	table := flow.NewTable(flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute, MaxFlows: 16384}, func(r flow.Record) {
		if len(records) < *maxRows {
			records = append(records, r)
		}
	})
	packets, errs := source.Packets(ctx)
	var tick time.Time
	for p := range packets {
		table.Observe(p)
		if tick.IsZero() || p.TS.Sub(tick) >= time.Second {
			table.Tick(p.TS)
			tick = p.TS
		}
		if len(records) >= *maxRows {
			cancel()
			break
		}
	}
	table.Flush()
	for e := range errs {
		if e != nil && !errors.Is(e, context.Canceled) {
			return errors.New("capture decoding failed")
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].LastSeen.Equal(records[j].LastSeen) {
			return records[i].ID < records[j].ID
		}
		return records[i].LastSeen.Before(records[j].LastSeen)
	})
	window := features.NewHostWindow()
	enc := json.NewEncoder(os.Stdout)
	for _, r := range records {
		base := features.Extract(r)
		v := features.Behavior(r, base)
		identity := fmt.Sprintf("%s/%s/%d/%s/%d/%d", r.Proto, r.InitiatorIP, r.InitiatorPort, r.ResponderIP, r.ResponderPort, r.FirstSeen.UnixNano())
		window.Apply(&v, features.HostSample{Sensor: digest, Initiator: r.InitiatorIP.String(), Responder: r.ResponderIP.String(), Identity: identity, Port: r.ResponderPort, At: r.LastSeen, Started: r.FirstSeen, SYNOnly: r.SynCount > 0 && r.AckCount == 0, OneWay: r.BwdPackets == 0, Bytes: float64(r.FwdBytes + r.BwdBytes), Telemetry: r.Telemetry})
		y := *label
		if y == "protocol_evidence" {
			y = ""
			if v.Values[128]+v.Values[129] > 0 {
				y = "dns"
			} else if v.Values[140] > 0 {
				y = "irc"
			} else if v.Values[137] > 0 || (v.Values[139] > 0 && base.Values[22] == 443) {
				y = "web"
			}
		}
		if *official != "" {
			y = ""
			key := tuple(strings.ToLower(r.Proto.String()), r.InitiatorIP.String(), int(r.InitiatorPort), r.ResponderIP.String(), int(r.ResponderPort))
			for _, l := range labels[key] {
				if !r.FirstSeen.Before(l.start.Add(-5*time.Second)) && !r.FirstSeen.After(l.end.Add(5*time.Second)) {
					if y != "" && y != l.label {
						y = ""
						break
					}
					y = l.label
				}
			}
		}
		if y == "" {
			continue
		}
		ch := sha256.Sum256([]byte(digest + identity))
		result := row{Values: v.Values, Label: y, Group: digest, Conversation: hex.EncodeToString(ch[:]), Time: float64(r.FirstSeen.UnixNano()) / 1e9}
		if e = enc.Encode(result); e != nil {
			return e
		}
	}
	return nil
}
func tuple(proto, src string, sp int, dst string, dp int) string {
	return fmt.Sprintf("%s|%s|%d|%s|%d", proto, src, sp, dst, dp)
}
func readLabels(path string) (map[string][]officialLabel, error) {
	out := map[string][]officialLabel{}
	if path == "" {
		return out, nil
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	rd := csv.NewReader(io.LimitReader(f, 64<<20))
	head, e := rd.Read()
	if e != nil {
		return nil, e
	}
	cols := map[string]int{}
	for i, h := range head {
		cols[h] = i
	}
	for _, k := range []string{"StartTime", "Dur", "Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "Label"} {
		if _, ok := cols[k]; !ok {
			return nil, errors.New("unsupported CTU label header")
		}
	}
	for count := 0; count < 1000000; count++ {
		v, e := rd.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("invalid CTU label row")
		}
		get := func(k string) string { return v[cols[k]] }
		raw := get("Label")
		label := ""
		if strings.Contains(raw, "From-Botnet") {
			label = "botnet_c2"
		} else if strings.Contains(raw, "From-Normal") {
			label = "normal"
		}
		if label == "" {
			continue
		}
		at, e := time.ParseInLocation("2006/01/02 15:04:05.000000", get("StartTime"), time.FixedZone("CTU CEST", 2*3600))
		if e != nil {
			return nil, errors.New("unsupported CTU timestamp")
		}
		dur, e := strconv.ParseFloat(get("Dur"), 64)
		if e != nil || dur < 0 || dur > 86400 {
			continue
		}
		sp, _ := strconv.ParseInt(get("Sport"), 0, 32)
		dp, _ := strconv.ParseInt(get("Dport"), 0, 32)
		if sp == 0 {
			sp, _ = strconv.ParseInt(get("Sport"), 10, 32)
		}
		if dp == 0 {
			dp, _ = strconv.ParseInt(get("Dport"), 10, 32)
		}
		k := tuple(get("Proto"), get("SrcAddr"), int(sp), get("DstAddr"), int(dp))
		out[k] = append(out[k], officialLabel{start: at, end: at.Add(time.Duration(dur * float64(time.Second))), label: label})
	}
	return out, nil
}
