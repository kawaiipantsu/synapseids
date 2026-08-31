package report

// HTML rendering of an investigation report.
//
// # Why html/template and not text/template
//
// Every string that reaches this template is untrusted (PROJECT.md §21, §28.11).
// Addresses, protocol names, sensor names, close reasons, model IDs and traffic
// class names arrive from decoded packets or from a model bundle; the filter
// description is echoed from a query string. The output is a document an
// operator opens in a browser, so an unescaped value is a stored-XSS sink in an
// artefact that then gets mailed around and re-opened elsewhere.
//
// html/template's contextual auto-escaping is the control. It escapes per
// context — element text, attribute value, URL, CSS, JS — and it is applied by
// the engine rather than by remembering to call a helper. text/template would
// compile and render identically for benign input and silently emit
// `<script>alert(1)</script>` verbatim for hostile input, which is exactly the
// failure mode a report must not have. TestHTMLEscapesHostileStrings feeds
// hostile markup through several report fields and asserts none of it survives
// as live markup.
//
// Two consequences of that choice are load-bearing:
//
//  1. **No untrusted value is ever placed in a CSS or URL context.** Bar widths
//     are the only computed style values, and they come from a Go-side float
//     formatted to a fixed pattern (see barPct), never from a packet-derived
//     string. There are no links, so there is no URL context at all.
//  2. **The document is entirely self-contained.** One inline <style>, no
//     external stylesheet, no CDN, no <script>, no <img>, no webfont. It opens
//     from file:// with no network access, and there is nothing loadable for a
//     crafted value to point at. TestHTMLHasNoExternalReferences asserts this.
//
// The palette mirrors web/ui/src/styles.css so a report looks like the SPA it
// came from, and a @media print block flips it to ink-on-white so the same file
// prints sensibly.

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// HTML renders the report as one standalone HTML document.
func (r *Report) HTML() ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, r.view()); err != nil {
		return nil, fmt.Errorf("report: render html: %w", err)
	}
	return buf.Bytes(), nil
}

// ------------------------------------------------------------------ view model
//
// The template renders a flattened view rather than the Report itself, so all
// the arithmetic (shares, bar widths, byte formatting) happens in Go where it is
// testable, and the template stays a layout. None of these helpers concatenate
// markup: every value they produce is plain text or a number, and the template
// interpolates it through html/template's escaper.

type barView struct {
	Label string
	Count uint64
	Pct   string // "0.0%".."100.0%", Go-formatted, never packet-derived
	// Class is a CSS class suffix from a closed table (see classSuffix), so the
	// per-class colour never needs a CSS interpolation context at all.
	Class string
}

type sparkView struct {
	// X, W, H and Y are pre-computed SVG rect geometry. All are Go-side
	// integers, so the SVG carries no untrusted value in an attribute.
	X, Y, W, H int
	Label      string
	Total      uint32
}

type kvView struct {
	K, V string
}

type reportView struct {
	*Report

	Title        string
	ScopeLine    string
	GeneratedStr string
	BuildStr     string
	WindowStr    string
	FilterStr    string

	ClassBars []barView
	PeerBars  []barView
	PortBars  []barView
	ProtoBars []barView

	Spark      []sparkView
	SparkW     int
	SparkH     int
	SparkFirst string
	SparkLast  string
	SparkPeak  uint32

	HostFacts []kvView
	Warnings  []Note
	Infos     []Note
}

// classSuffixes maps a traffic-classes-v1 name to the CSS class suffix that
// colours it. The table is closed and the values are fixed identifiers, so a
// class name — which reaches us from a model bundle and is therefore untrusted —
// is never interpolated into a stylesheet or a style attribute. It picks a
// pre-declared rule or falls through to "dim".
//
// This is deliberate: html/template's cssValueFilter would reject a `var(--x)`
// value anyway, and routing colour through a class keeps the document free of
// any CSS interpolation context for untrusted data.
var classSuffixes = map[string]string{
	"normal":      "normal",
	"scan":        "scan",
	"dos_ddos":    "dos",
	"brute_force": "brute",
	"botnet_c2":   "c2",
	"web_attack":  "web",
	"suspicious":  "susp",
}

func classSuffix(name string) string {
	if v, ok := classSuffixes[name]; ok {
		return v
	}
	return "dim"
}

// barPct formats a bar width. The result is always a plain "N.N%" produced by
// Go, so the style attribute it lands in can never carry attacker input.
func barPct(n, max uint64) string {
	if max == 0 {
		return "0.0%"
	}
	p := float64(n) / float64(max) * 100
	if p < 1.5 {
		p = 1.5 // keep a non-zero row visible
	}
	if p > 100 {
		p = 100
	}
	return fmt.Sprintf("%.1f%%", p)
}

func (r *Report) view() reportView {
	v := reportView{Report: r, SparkW: 720, SparkH: 90}

	switch r.Scope.Kind {
	case ScopeHost:
		v.Title = "Host investigation report"
		v.ScopeLine = r.Scope.Host
	default:
		v.Title = "Time-window investigation report"
		v.ScopeLine = "all observed traffic in the window"
	}
	v.GeneratedStr = r.GeneratedAt.Format(time.RFC1123)
	dirty := ""
	if r.Generator.Dirty {
		dirty = " (dirty working tree)"
	}
	v.BuildStr = fmt.Sprintf("synapsed v%s · commit %s · built %s%s",
		r.Generator.Version, r.Generator.Commit, r.Generator.BuiltAt, dirty)

	switch {
	case r.Scope.Unbounded:
		v.WindowStr = "unbounded — whatever the daemon still retains"
	case r.Scope.From.IsZero():
		v.WindowStr = "up to " + fmtTime(r.Scope.To)
	case r.Scope.To.IsZero():
		v.WindowStr = "from " + fmtTime(r.Scope.From)
	default:
		v.WindowStr = fmtTime(r.Scope.From) + " → " + fmtTime(r.Scope.To)
	}
	v.FilterStr = r.Scope.Filter
	if v.FilterStr == "" {
		v.FilterStr = "none"
	}

	var maxClass uint64
	for _, c := range r.Classes {
		if c.Count > maxClass {
			maxClass = c.Count
		}
	}
	for _, c := range r.Classes {
		v.ClassBars = append(v.ClassBars, barView{
			Label: c.Class, Count: c.Count,
			Pct: barPct(c.Count, maxClass), Class: classSuffix(c.Class),
		})
	}

	var maxPeer, maxPort, maxProto uint64
	for _, p := range r.TopPeers {
		if p.Flows > maxPeer {
			maxPeer = p.Flows
		}
	}
	for _, p := range r.TopPorts {
		if p.Flows > maxPort {
			maxPort = p.Flows
		}
	}
	for _, p := range r.Protocols {
		if p.Flows > maxProto {
			maxProto = p.Flows
		}
	}
	for _, p := range r.TopPeers {
		v.PeerBars = append(v.PeerBars, barView{Label: p.IP, Count: p.Flows, Pct: barPct(p.Flows, maxPeer), Class: "accent"})
	}
	for _, p := range r.TopPorts {
		v.PortBars = append(v.PortBars, barView{Label: fmt.Sprint(p.Port), Count: p.Flows, Pct: barPct(p.Flows, maxPort), Class: "accent"})
	}
	for _, p := range r.Protocols {
		v.ProtoBars = append(v.ProtoBars, barView{Label: p.Proto, Count: p.Flows, Pct: barPct(p.Flows, maxProto), Class: "accent"})
	}

	v.Spark, v.SparkPeak, v.SparkFirst, v.SparkLast = spark(r.Timeline, v.SparkW, v.SparkH)

	if r.Host != nil {
		h := r.Host
		v.HostFacts = []kvView{
			{"address", h.IP},
			{"first seen", fmtTime(h.FirstSeen)},
			{"last seen", fmtTime(h.LastSeen)},
			{"flows (lifetime)", fmtUint(h.Flows)},
			{"initiated / answered", fmtUint(h.FlowsInitiated) + " / " + fmtUint(h.FlowsResponded)},
			{"bytes in / out", fmtBytes(h.BytesIn) + " / " + fmtBytes(h.BytesOut)},
			{"packets in / out", fmtUint(h.PacketsIn) + " / " + fmtUint(h.PacketsOut)},
			{"verdicts (lifetime)", fmtUint(h.Classifications)},
			{"model disagreements", fmtUint(h.Disagreements)},
		}
	}

	for _, n := range r.Notes {
		if n.Level == LevelWarning {
			v.Warnings = append(v.Warnings, n)
		} else {
			v.Infos = append(v.Infos, n)
		}
	}
	return v
}

// spark lays out the timeline as inline-SVG rect geometry. Nothing here is
// untrusted: the series is counts and bucket timestamps.
func spark(t Timeline, w, h int) (bars []sparkView, peak uint32, first, last string) {
	if len(t.Buckets) == 0 {
		return nil, 0, "", ""
	}
	// Downsample so a 1440-bucket series still yields readable bars.
	const maxBars = 180
	step := 1
	if len(t.Buckets) > maxBars {
		step = (len(t.Buckets) + maxBars - 1) / maxBars
	}
	type agg struct {
		total uint32
		ts    time.Time
	}
	groups := make([]agg, 0, maxBars)
	for i := 0; i < len(t.Buckets); i += step {
		g := agg{ts: t.Buckets[i].TS}
		for j := i; j < i+step && j < len(t.Buckets); j++ {
			g.total += t.Buckets[j].Total
		}
		groups = append(groups, g)
	}
	for _, g := range groups {
		if g.total > peak {
			peak = g.total
		}
	}
	bw := w / len(groups)
	if bw < 1 {
		bw = 1
	}
	for i, g := range groups {
		bh := 1
		if peak > 0 && g.total > 0 {
			bh = int(float64(g.total) / float64(peak) * float64(h-2))
			if bh < 1 {
				bh = 1
			}
		}
		bars = append(bars, sparkView{
			X: i * bw, W: max(bw-1, 1), H: bh, Y: h - bh,
			Label: g.ts.UTC().Format(time.RFC3339), Total: g.total,
		})
	}
	first = groups[0].ts.UTC().Format(time.RFC3339)
	last = groups[len(groups)-1].ts.UTC().Format(time.RFC3339)
	return bars, peak, first, last
}

func fmtUint(n uint64) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func fmtBytes(n uint64) string {
	const k = 1024.0
	f := float64(n)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for f >= k && i < len(units)-1 {
		f /= k
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// templateFuncs are all pure formatters. None of them produces markup, and none
// returns template.HTML/JS/CSS — so no value can bypass the auto-escaper.
var templateFuncs = template.FuncMap{
	"uint":  fmtUint,
	"bytes": fmtBytes,
	"time":  fmtTime,
	"pct": func(f float64) string {
		return fmt.Sprintf("%.1f%%", f*100)
	},
	"num": func(f float64) string {
		if f == float64(int64(f)) {
			return fmt.Sprintf("%d", int64(f))
		}
		return fmt.Sprintf("%.4g", f)
	},
	"dur": func(sec float64) string {
		if sec < 1 {
			return fmt.Sprintf("%.0f ms", sec*1000)
		}
		return fmt.Sprintf("%.2f s", sec)
	},
	"classSuffix": classSuffix,
	"join":        func(v []string) string { return strings.Join(v, ", ") },
}

var htmlTemplate = template.Must(template.New("report").Funcs(templateFuncs).Parse(reportHTML))

// reportHTML is the whole document. Deliberately: one inline <style>, zero
// external references, zero script. Everything interpolated goes through
// html/template's contextual escaping.
const reportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{{.Generator.Product}} {{.Generator.Version}}">
<meta name="robots" content="noindex, nofollow">
<title>SynapseIDS — {{.Title}} — {{.ScopeLine}}</title>
<style>
:root{
  --bg:#0b1f28; --panel:#0f2b37; --panel2:#10323f; --edge:#1c4a5c;
  --ink:#dfeef3; --dim:#7fa6b4; --accent:#35c1d6;
  --normal:#4a6b78; --scan:#ffb454; --dos:#ff5c6c; --brute:#ff8f40;
  --c2:#c586ff; --web:#ff79c6; --suspicious:#ffd166;
  --warn:#ffb454; --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:13px/1.55 var(--mono)}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 64px}
h1{font-size:20px;margin:0 0 2px}
h2{font-size:14px;margin:26px 0 8px;color:var(--accent);border-bottom:1px solid var(--edge);padding-bottom:5px;
   text-transform:uppercase;letter-spacing:.09em}
h3{font-size:12px;margin:0 0 8px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em}
.sub{color:var(--dim)}
.mono{font-family:var(--mono)}
.hd{border:1px solid var(--edge);background:var(--panel);border-radius:8px;padding:16px 18px;margin-bottom:6px}
.hd .scope{font-size:22px;font-weight:700;color:var(--accent);word-break:break-all}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:4px 22px;margin-top:12px}
.meta div{display:flex;gap:8px}
.meta b{color:var(--dim);font-weight:400;min-width:104px;flex:0 0 auto}
/* Break only where a break is needed, and prefer existing spaces — unlike
   .wordy, which is for values with no natural break point (an IPv6 literal). */
.softwrap{overflow-wrap:break-word;word-break:normal}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:12px 0}
.card{border:1px solid var(--edge);background:var(--panel);border-radius:8px;padding:11px 13px}
.card .big{font-size:21px;font-weight:700}
.card .foot{color:var(--dim);font-size:11px;margin-top:2px}
.panel{border:1px solid var(--edge);background:var(--panel);border-radius:8px;padding:13px 15px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid4{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px}
.note{border:1px solid var(--edge);border-left:4px solid var(--dim);background:var(--panel2);
      border-radius:6px;padding:9px 12px;margin:7px 0}
.note.warn{border-left-color:var(--warn)}
.note code{color:var(--dim);font-size:11px}
.note p{margin:3px 0 0}
.barrow{display:grid;grid-template-columns:150px 1fr 78px;gap:9px;align-items:center;margin:3px 0}
.barrow .lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.track{background:var(--panel2);border:1px solid var(--edge);border-radius:4px;height:12px;overflow:hidden}
.fill{display:block;height:100%;background:var(--dim)}
/* Closed set of bar/pill colours, selected by a Go-side class suffix. No
   untrusted value ever reaches a CSS context. */
.f-accent{background:var(--accent)}
.f-normal{background:var(--normal)}
.f-scan{background:var(--scan)}
.f-dos{background:var(--dos)}
.f-brute{background:var(--brute)}
.f-c2{background:var(--c2)}
.f-web{background:var(--web)}
.f-susp{background:var(--suspicious)}
.f-dim{background:var(--dim)}
.n{text-align:right;color:var(--dim)}
table{border-collapse:collapse;width:100%;font-size:11.5px}
th,td{border-bottom:1px solid var(--edge);padding:5px 7px;text-align:left;vertical-align:top}
th{color:var(--dim);font-weight:600;white-space:nowrap;text-transform:uppercase;letter-spacing:.05em;font-size:10px}
td.num,th.num{text-align:right}
tr.dis{background:rgba(255,92,108,.10)}
.pill{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;color:#04222a;background:var(--dim)}
.tag{display:inline-block;padding:1px 6px;border:1px solid var(--edge);border-radius:9px;font-size:10px;color:var(--dim)}
.tag.bad{border-color:var(--dos);color:var(--dos)}
.svgwrap{overflow-x:auto}
.ftab{width:100%;font-size:11px;margin-top:5px}
.dim{color:var(--dim)}
.wordy{word-break:break-all}
.kvk{width:220px}
.kvw{width:290px}
details{margin:6px 0}
summary{cursor:pointer;color:var(--accent)}
footer{margin-top:34px;color:var(--dim);font-size:11px;border-top:1px solid var(--edge);padding-top:11px}
@media print{
  :root{--bg:#fff;--panel:#fff;--panel2:#f4f6f7;--edge:#b9c6cc;--ink:#101416;--dim:#4a5a61;
        --accent:#0d5a68;color-scheme:light}
  body{background:#fff;color:#101416;font-size:9.5pt}
  .wrap{max-width:none;padding:0}
  h2{page-break-after:avoid}
  .panel,.card,.note,.hd{break-inside:avoid}
  tr{break-inside:avoid}
  .pill{color:#101416;border:1px solid #b9c6cc}
  details{display:block}
  details>summary{display:none}
  footer{page-break-before:avoid}
}
</style>
</head>
<body>
<div class="wrap">

<div class="hd">
  <h1>SynapseIDS — {{.Title}}</h1>
  <div class="scope mono">{{.ScopeLine}}</div>
  <div class="meta">
    <div><b>generated</b><span>{{.GeneratedStr}}</span></div>
    <div><b>build</b><span class="softwrap">{{.BuildStr}}</span></div>
    <div><b>window</b><span class="softwrap">{{.WindowStr}}</span></div>
    <div><b>filter</b><span class="wordy">{{.FilterStr}}</span></div>
    <div><b>schemas</b><span>{{.Generator.FeatureSchema}} / {{.Generator.OutputSchema}}</span></div>
    <div><b>report schema</b><span>{{.Schema}}</span></div>
  </div>
</div>
<p class="sub">Self-contained snapshot. Nothing in this file loads from the network; it is
a point-in-time copy of daemon state and does not update.
{{if .Coverage.Partial}}<span class="tag bad">partial view — see caveats</span>{{end}}</p>

<h2>What this report does not tell you</h2>
{{range .Warnings}}
<div class="note warn"><code>{{.Code}}</code><p>{{.Text}}</p></div>
{{end}}
{{range .Infos}}
<div class="note"><code>{{.Code}}</code><p>{{.Text}}</p></div>
{{end}}

<h2>Summary — verdicts in scope</h2>
<div class="cards">
  <div class="card"><h3>Verdicts</h3><div class="big">{{uint .Summary.Classifications}}</div>
    <div class="foot">{{.Summary.DistinctFlows}} distinct flows</div></div>
  <div class="card"><h3>Non-normal</h3><div class="big">{{uint .Summary.NonNormal}}</div>
    <div class="foot">class other than normal</div></div>
  <div class="card"><h3>Disagreements</h3><div class="big">{{uint .Summary.Disagreements}}</div>
    <div class="foot">models did not agree</div></div>
  <div class="card"><h3>Hosts in scope</h3><div class="big">{{.Summary.DistinctHosts}}</div>
    <div class="foot">distinct addresses</div></div>
  <div class="card"><h3>First verdict</h3><div class="big">{{if .Summary.FirstVerdict.IsZero}}—{{else}}{{.Summary.FirstVerdict.Format "15:04:05"}}{{end}}</div>
    <div class="foot">{{time .Summary.FirstVerdict}}</div></div>
  <div class="card"><h3>Last verdict</h3><div class="big">{{if .Summary.LastVerdict.IsZero}}—{{else}}{{.Summary.LastVerdict.Format "15:04:05"}}{{end}}</div>
    <div class="foot">{{time .Summary.LastVerdict}}</div></div>
</div>

{{if .HostFacts}}
<h2>Host profile</h2>
<div class="panel">
  <table>
    <tbody>
    {{range .HostFacts}}<tr><th class="kvk">{{.K}}</th><td class="mono wordy">{{.V}}</td></tr>{{end}}
    </tbody>
  </table>
  <p class="dim">Lifetime counters from the aggregation index; they may be wider than the
  reported window. The in-scope numbers are in Summary above.</p>
</div>
{{end}}

<h2>Classification mix</h2>
<div class="panel">
{{if .ClassBars}}
  {{range .ClassBars}}
  <div class="barrow">
    <span class="lbl" title="{{.Label}}">{{.Label}}</span>
    <span class="track"><span class="fill f-{{.Class}}" style="width:{{.Pct}}"></span></span>
    <span class="n">{{uint .Count}}</span>
  </div>
  {{end}}
{{else}}
  <p class="dim">No verdicts in scope.</p>
{{end}}
</div>

<h2>Classification timeline</h2>
<div class="panel">
{{if .Spark}}
  <div class="svgwrap">
  <svg width="{{.SparkW}}" height="{{.SparkH}}" viewBox="0 0 {{.SparkW}} {{.SparkH}}"
       role="img" aria-label="classification volume over the reported window">
    <rect x="0" y="0" width="{{.SparkW}}" height="{{.SparkH}}" fill="none"/>
    {{range .Spark}}<rect x="{{.X}}" y="{{.Y}}" width="{{.W}}" height="{{.H}}" fill="#35c1d6"><title>{{.Label}} — {{.Total}}</title></rect>
    {{end}}
  </svg>
  </div>
  <p class="dim">{{.Timeline.BucketSec}}s buckets · peak {{.SparkPeak}} verdicts ·
  {{.SparkFirst}} → {{.SparkLast}} · source: {{.Timeline.Source}}</p>
{{else}}
  <p class="dim">No timeline buckets in the retained window. This is an absence of retained
  data, not a statement that the window was quiet.</p>
{{end}}
  <p class="dim">There is no anomaly series: anomaly scoring is Phase 7 and this build
  computes none, so none is plotted.</p>
</div>

<h2>Peers, service ports and protocols</h2>
<div class="grid4">
  <div class="panel"><h3>Top peers</h3>
  {{if .PeerBars}}{{range .PeerBars}}
    <div class="barrow"><span class="lbl" title="{{.Label}}">{{.Label}}</span>
      <span class="track"><span class="fill f-{{.Class}}" style="width:{{.Pct}}"></span></span>
      <span class="n">{{uint .Count}}</span></div>
  {{end}}{{else}}<p class="dim">none recorded</p>{{end}}
  </div>
  <div class="panel"><h3>Top service ports</h3>
  {{if .PortBars}}{{range .PortBars}}
    <div class="barrow"><span class="lbl" title="{{.Label}}">{{.Label}}</span>
      <span class="track"><span class="fill f-{{.Class}}" style="width:{{.Pct}}"></span></span>
      <span class="n">{{uint .Count}}</span></div>
  {{end}}{{else}}<p class="dim">none recorded</p>{{end}}
  </div>
  <div class="panel"><h3>Protocols</h3>
  {{if .ProtoBars}}{{range .ProtoBars}}
    <div class="barrow"><span class="lbl" title="{{.Label}}">{{.Label}}</span>
      <span class="track"><span class="fill f-{{.Class}}" style="width:{{.Pct}}"></span></span>
      <span class="n">{{uint .Count}}</span></div>
  {{end}}{{else}}<p class="dim">none recorded</p>{{end}}
  </div>
</div>

<h2>Active model set at generation time</h2>
<div class="panel">
{{if .Models}}
<table>
  <thead><tr><th>model id</th><th>family</th><th>role</th></tr></thead>
  <tbody>{{range .Models}}<tr><td class="mono wordy">{{.ID}}</td><td>{{.Family}}</td><td>{{.Role}}</td></tr>{{end}}</tbody>
</table>
{{else}}<p class="dim">No classifier was loaded.</p>{{end}}
</div>

<h2>Notable flows — {{len .NotableFlows}} listed{{if .Coverage.NotableFlowsTruncated}} of {{.Coverage.NotableCandidates}} candidates{{end}}</h2>
<p class="sub">Selected because the ensemble disagreed, or the verdict was not
<code>normal</code>. Ordered: disagreements first, then descending confidence.</p>
<div class="panel">
{{if .NotableFlows}}
<table>
  <thead><tr>
    <th class="num">flow</th><th>time (UTC)</th><th>proto</th><th>initiator</th><th>responder</th>
    <th>verdict</th><th class="num">conf</th><th class="num">dur</th>
    <th class="num">pkts</th><th class="num">bytes</th><th>why</th>
  </tr></thead>
  <tbody>
  {{range .NotableFlows}}
  <tr{{if .Disagreement}} class="dis"{{end}}>
    <td class="num mono">{{.FlowID}}</td>
    <td class="mono">{{.TS.Format "2006-01-02 15:04:05"}}</td>
    <td>{{.Proto}}</td>
    <td class="mono wordy">{{.InitiatorIP}}:{{.InitiatorPort}}</td>
    <td class="mono wordy">{{.ResponderIP}}:{{.ResponderPort}}</td>
    <td><span class="pill f-{{classSuffix .Class}}">{{.Class}}</span></td>
    <td class="num">{{pct .Score}}</td>
    <td class="num">{{if .RecordAvailable}}{{dur .DurationSec}}{{else}}—{{end}}</td>
    <td class="num">{{if .RecordAvailable}}{{uint .FwdPackets}}/{{uint .BwdPackets}}{{else}}—{{end}}</td>
    <td class="num">{{if .RecordAvailable}}{{bytes .FwdBytes}}/{{bytes .BwdBytes}}{{else}}—{{end}}</td>
    <td>{{join .Reasons}}{{if not .RecordAvailable}} <span class="tag bad">record evicted</span>{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p class="dim">No flow in scope disagreed across models or produced a non-normal verdict.
Note that this only covers the verdicts this report actually walked — see the caveats above.</p>
{{end}}
</div>

<h2>Notable flows — per-model outputs and raw feature values</h2>
<p class="sub">Every model's own output is kept alongside the combined verdict
(PROJECT.md §12); the combined verdict is never the only thing recorded. Feature
values are raw <code>{{.Generator.FeatureSchema}}</code> values, not normalized model inputs.</p>
{{range .NotableFlows}}
<details{{if .Disagreement}} open{{end}}>
<summary>flow {{.FlowID}} · {{.Proto}} {{.InitiatorIP}}:{{.InitiatorPort}} → {{.ResponderIP}}:{{.ResponderPort}} · {{.Class}} {{pct .Score}}{{if .Disagreement}} · DISAGREEMENT{{end}}</summary>
<div class="panel">
  <div class="grid2">
    <div>
      <h3>Per-model output</h3>
      {{if .Models}}
      <table><thead><tr><th>model</th><th>role</th><th>class</th><th class="num">score</th></tr></thead>
      <tbody>{{range .Models}}<tr><td class="mono wordy">{{.ModelID}}</td><td>{{.Role}}</td><td>{{.Class}}</td><td class="num">{{pct .Score}}</td></tr>{{end}}</tbody></table>
      {{else}}<p class="dim">no per-model breakdown stored</p>{{end}}
      {{if .Sensor}}<p class="dim">sensor: <span class="mono">{{.Sensor}}</span></p>{{end}}
      {{if .RecordAvailable}}
      <p class="dim">first seen {{time .FirstSeen}} · last seen {{time .LastSeen}} · closed: {{.CloseReason}}</p>
      {{else}}
      <p class="dim">The flow record behind this verdict has been evicted from the bounded
      store, so its timing, volume and feature values are unavailable.</p>
      {{end}}
    </div>
    <div>
      <h3>Raw feature values</h3>
      {{if .Features}}
      <table class="ftab"><thead><tr><th>feature</th><th class="num">value</th><th>unit</th></tr></thead>
      <tbody>{{range .Features}}<tr><td>{{.Name}}</td><td class="num">{{num .Value}}</td><td class="dim">{{.Unit}}</td></tr>{{end}}</tbody></table>
      {{else}}<p class="dim">unavailable — flow record evicted</p>{{end}}
    </div>
  </div>
</div>
</details>
{{end}}

<h2>Feature legend</h2>
<div class="panel">
<table><thead><tr><th>feature</th><th>unit</th><th>calculation</th></tr></thead>
<tbody>{{range .FeatureLegend}}<tr><td class="mono">{{.Name}}</td><td class="dim">{{.Unit}}</td><td class="dim">{{.Calc}}</td></tr>{{end}}</tbody></table>
</div>

<h2>Coverage and limits</h2>
<div class="panel">
<table>
<tbody>
<tr><th class="kvw">partial view</th><td>{{if .Coverage.Partial}}YES — see the caveats at the top{{else}}no limit was hit for this scope{{end}}</td></tr>
<tr><th>record store</th><td>driver {{.Coverage.StoreDriver}} · retaining {{.Coverage.FlowsRetained}} flows / {{.Coverage.ClassificationsRetained}} verdicts · evicted {{uint .Coverage.FlowsEvicted}} flows / {{uint .Coverage.ClassificationsEvicted}} verdicts</td></tr>
<tr><th>verdicts walked</th><td>{{.Coverage.ScanScanned}} of a {{.Coverage.ScanLimit}} budget{{if .Coverage.ScanExhausted}} — budget exhausted{{end}} · oldest retained {{time .Coverage.OldestRetained}}</td></tr>
<tr><th>host profiles</th><td>{{.Coverage.HostsTracked}} tracked, cap {{.Coverage.HostCap}} · {{uint .Coverage.HostsEvicted}} evicted</td></tr>
<tr><th>per-host top-N</th><td>cap {{.Coverage.KeyCap}} distinct ports/peers · {{uint .Coverage.KeysPruned}} low-count keys pruned</td></tr>
<tr><th>aggregation queue</th><td>{{uint .Coverage.ObservationsDropped}} observations dropped · {{uint .Coverage.TimelineLate}} verdicts too late for a timeline bucket</td></tr>
<tr><th>notable flows</th><td>{{.Coverage.NotableCandidates}} candidates, cap {{.Coverage.NotableFlowCap}}{{if .Coverage.NotableFlowsTruncated}} — TRUNCATED{{end}} · {{.Coverage.FlowRecordsMissing}} without a retained flow record</td></tr>
<tr><th>behavioural baseline</th><td>{{if .Coverage.BaselineAvailable}}available{{else}}NOT AVAILABLE IN THIS BUILD (Phase 7){{end}}</td></tr>
<tr><th>anomaly score</th><td>{{if .Coverage.AnomalyAvailable}}available{{else}}NOT AVAILABLE IN THIS BUILD (Phase 7){{end}}</td></tr>
</tbody>
</table>
</div>

<footer>
Generated by {{.BuildStr}} at {{.GeneratedStr}} · report schema {{.Schema}} ·
This document contains sensitive network telemetry: it enumerates observed addresses and
how they behave. Handle it accordingly.
</footer>

</div>
</body>
</html>
`
