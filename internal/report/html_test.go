package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	texttemplate "text/template"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// hostile is the injection corpus. Each entry is fed through report fields that
// carry packet- or request-derived data, and none of it may survive as live
// markup in the rendered document.
//
// This is the control §28.11 asks for: a crafted hostname, sensor name or filter
// string must not be able to inject anything into a report an operator opens in
// a browser — a report is precisely the artefact that gets forwarded and opened
// somewhere with fewer defences than the SPA.
var hostile = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`'><svg/onload=alert(1)>`,
	`</style><script>alert(1)</script>`,
	`</title><script>alert(1)</script>`,
	`javascript:alert(1)`,
	`" onmouseover="alert(1)`,
	`</textarea></noscript><iframe src=//evil.example>`,
	"line1\r\nline2: <b>x</b>",
	`{{.}}{{template "x"}}`,
	`--></style><style>body{background:url(//evil.example/x)}`,
}

// buildHostileReport puts every hostile string somewhere a real report would
// carry untrusted data: the host address, a peer address, the protocol name, a
// sensor name, a close reason, a model id, a traffic-class name and the echoed
// filter description.
func buildHostileReport(t *testing.T, payload string) *Report {
	t.Helper()

	store := storage.NewMem(64, 64)
	ix := insight.New(insight.Options{})
	t.Cleanup(func() { _ = ix.Close() })

	ts := base
	fr := storage.FlowRecord{
		ID:            1,
		Proto:         payload, // decoder-derived string
		InitiatorIP:   payload, // packet-derived address
		InitiatorPort: 4444,
		ResponderIP:   payload + "/peer",
		ResponderPort: 3306,
		FirstSeen:     ts.Add(-time.Second),
		LastSeen:      ts,
		DurationSec:   1,
		FwdPackets:    4,
		BwdPackets:    2,
		FwdBytes:      400,
		BwdBytes:      120,
		CloseReason:   payload, // flow-engine string
		Features:      features.Vector{FlowID: 1, Schema: features.SchemaID},
	}
	cl := storage.Classification{
		FlowID:        1,
		TS:            ts,
		Sensor:        payload, // sensor-supplied name
		Proto:         payload,
		InitiatorIP:   payload,
		InitiatorPort: 4444,
		ResponderIP:   payload + "/peer",
		ResponderPort: 3306,
		Result: inference.Result{
			FlowID:       1,
			Class:        payload, // a model bundle could name a class anything
			ClassID:      99,      // deliberately out of range
			Score:        0.93,
			Disagreement: true,
			Models: []inference.ModelOutput{{
				ModelID: payload, // bundle-supplied model id
				Role:    inference.Role(payload),
				Class:   payload,
				Score:   0.93,
			}},
		},
	}
	store.PutFlow(fr)
	store.PutClassification(cl)
	ix.Observe(&fr, &cl)
	ix.Sync()

	src := Sources{
		Store:   store,
		Insight: ix,
		Runtime: inference.NewRuntime(inference.NewHeuristic(payload, inference.Role(payload))),
	}
	opt := Options{
		Scope:       ScopeHost,
		Host:        payload,
		GeneratedAt: base,
		BucketSec:   1,
		FilterDesc:  payload, // request-derived echo
		Keep:        func(storage.Classification) bool { return true },
	}
	r, err := Build(src, opt)
	if err != nil {
		t.Fatalf("Build with hostile input: %v", err)
	}
	return r
}

// TestHTMLEscapesHostileStrings is the injection test PROJECT.md §28.11 demands.
// It asserts three things for every payload:
//
//  1. the payload reaches the report at all (otherwise the test proves nothing);
//  2. the raw payload does not appear verbatim in the HTML; and
//  3. no live markup — no <script>, no event handler, no <iframe>/<img>/<svg> —
//     appears anywhere in the output.
func TestHTMLEscapesHostileStrings(t *testing.T) {
	for _, payload := range hostile {
		t.Run(payload, func(t *testing.T) {
			r := buildHostileReport(t, payload)

			// (1) The payload really is in the document model.
			if r.Scope.Host != payload {
				t.Fatalf("payload did not reach Scope.Host: %q", r.Scope.Host)
			}
			if r.Scope.Filter != payload {
				t.Fatalf("payload did not reach Scope.Filter: %q", r.Scope.Filter)
			}
			if len(r.NotableFlows) == 0 {
				t.Fatal("payload did not reach the notable-flow table")
			}

			out, err := r.HTML()
			if err != nil {
				t.Fatalf("HTML: %v", err)
			}
			got := string(out)

			// (2) The payload does not appear verbatim anywhere. This is the
			// strongest single assertion: if the raw bytes are absent, no markup
			// they encode can have been produced.
			if strings.ContainsAny(payload, `<>"'`) && strings.Contains(got, payload) {
				t.Fatalf("payload survived verbatim in the rendered HTML\n--- context ---\n%s",
					context(got, payload))
			}

			// (3) Structural check. Escaping means every '<' left in the output
			// belongs to the template's own literal markup, so scanning the tags
			// proves the payload created no element and no attribute: an
			// injected tag would show up as a name outside the allowlist, and an
			// injected handler as an on* attribute inside a tag span.
			//
			// This is stronger than substring matching, which cannot tell the
			// inert text "onerror=" (correctly escaped, harmless) from a live
			// attribute.
			for _, tag := range tagSpans(got) {
				name := tagName(tag)
				if !allowedTags[name] {
					t.Fatalf("unexpected element <%s> in the document — injected markup?\n%s", name, tag)
				}
				if name == "!doctype" {
					continue // not an element; "html" is its literal token
				}
				// Quoted attribute *values* are safe by construction: a '"'
				// inside one is escaped to &#34;, so every '"' in the span is a
				// real delimiter. Strip the values and inspect the skeleton —
				// that is where an injected attribute would have to appear.
				for _, attr := range attrNames(tag) {
					if !allowedAttrs[attr] {
						t.Fatalf("unexpected attribute %q on <%s> — injected attribute?\n%s", attr, name, tag)
					}
					if strings.HasPrefix(attr, "on") {
						t.Fatalf("event handler %q reached the document:\n%s", attr, tag)
					}
				}
			}

			// (4) The escaped form is what we see instead: the '<' of the
			// payload became an entity.
			if strings.Contains(payload, "<") && !strings.Contains(got, "&lt;") {
				t.Fatal("payload contained '<' but no escaped '&lt;' appears — is the value being rendered at all?")
			}

			// (5) An out-of-range / unknown class name must fall through the
			// closed colour table, never be interpolated into a style.
			if strings.Contains(got, "f-"+payload) {
				t.Fatalf("class suffix interpolated an untrusted value: %s", context(got, "f-"))
			}
			if strings.Contains(got, "ZgotmplZ") {
				t.Fatalf("html/template had to blank a value it could not vouch for:\n%s",
					context(got, "ZgotmplZ"))
			}
		})
	}
}

// TestTextTemplateWouldNotEscape is the negative control for the test above. It
// renders the *same* template source through text/template and asserts the
// hostile payload comes out verbatim, complete with a live <script> element.
//
// Without this, TestHTMLEscapesHostileStrings could pass for the wrong reason —
// a value that is never rendered is trivially "escaped". This proves the payload
// really does reach the document, and that html/template's contextual escaping
// is the thing preventing the injection rather than an accident of layout. It is
// also why the ADR records html/template as a security control and not a
// stylistic preference (PROJECT.md §21, §28.11).
func TestTextTemplateWouldNotEscape(t *testing.T) {
	const payload = `<script>alert(1)</script>`
	r := buildHostileReport(t, payload)

	unsafe := texttemplate.Must(texttemplate.New("report").Funcs(templateFuncs).Parse(reportHTML))
	var buf bytes.Buffer
	if err := unsafe.Execute(&buf, r.view()); err != nil {
		t.Fatalf("text/template execute: %v", err)
	}
	if !strings.Contains(buf.String(), payload) {
		t.Fatal("text/template did not emit the payload verbatim — the control test " +
			"is not exercising a real injection path any more")
	}

	// And the html/template rendering of the very same view does not.
	safe, err := r.HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if strings.Contains(string(safe), payload) {
		t.Fatal("html/template emitted the payload verbatim")
	}
	if !strings.Contains(string(safe), "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("html/template output does not contain the escaped payload")
	}
}

// allowedTags is every element the report template is allowed to emit. Anything
// else in the rendered output can only have come from an interpolated value,
// which is exactly the failure the escaping is there to prevent.
var allowedTags = map[string]bool{
	"!doctype": true, "html": true, "/html": true,
	"head": true, "/head": true, "meta": true,
	"title": true, "/title": true, "style": true, "/style": true,
	"body": true, "/body": true, "div": true, "/div": true,
	"h1": true, "/h1": true, "h2": true, "/h2": true, "h3": true, "/h3": true,
	"p": true, "/p": true, "span": true, "/span": true,
	"table": true, "/table": true, "thead": true, "/thead": true,
	"tbody": true, "/tbody": true, "tr": true, "/tr": true,
	"th": true, "/th": true, "td": true, "/td": true,
	"svg": true, "/svg": true, "rect": true, "/rect": true,
	"details": true, "/details": true, "summary": true, "/summary": true,
	"footer": true, "/footer": true, "code": true, "/code": true,
	"b": true, "/b": true,
}

// allowedAttrs is every attribute the report template is allowed to emit. There
// is deliberately no URL-bearing attribute in the set — no href, no src, no
// action — so the document has no URL context for an interpolated value to
// land in at all.
var allowedAttrs = map[string]bool{
	"lang": true, "charset": true, "name": true, "content": true,
	"class": true, "style": true, "title": true, "open": true,
	"width": true, "height": true, "viewbox": true, "role": true,
	"aria-label": true, "x": true, "y": true, "fill": true,
}

// attrNames returns the lowercased attribute names in a `<...>` span, ignoring
// quoted values (which html/template has already escaped).
func attrNames(tag string) []string {
	t := strings.TrimSuffix(strings.TrimPrefix(tag, "<"), ">")
	// Drop the element name.
	if i := strings.IndexAny(t, " \t\r\n"); i >= 0 {
		t = t[i+1:]
	} else {
		return nil
	}
	var out []string
	for i := 0; i < len(t); {
		// Skip separators.
		for i < len(t) && (t[i] == ' ' || t[i] == '\t' || t[i] == '\r' || t[i] == '\n' || t[i] == '/') {
			i++
		}
		start := i
		for i < len(t) && t[i] != '=' && t[i] != ' ' && t[i] != '\t' && t[i] != '\r' && t[i] != '\n' && t[i] != '/' {
			i++
		}
		if start < i {
			out = append(out, strings.ToLower(t[start:i]))
		}
		if i < len(t) && t[i] == '=' {
			i++
			if i < len(t) && (t[i] == '"' || t[i] == '\'') {
				q := t[i]
				i++
				for i < len(t) && t[i] != q { // the value is escaped; skip it
					i++
				}
				i++ // past the closing quote
			} else {
				for i < len(t) && t[i] != ' ' && t[i] != '\t' && t[i] != '\r' && t[i] != '\n' {
					i++
				}
			}
		}
	}
	return out
}

// tagSpans returns every `<...>` span in s. Because html/template escapes '<'
// in interpolated data to "&lt;", every span it finds is template-literal
// markup — which is the point: if a payload ever produced a span, it means the
// escaping failed.
func tagSpans(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			break
		}
		out = append(out, s[i:i+j+1])
		i += j
	}
	return out
}

// tagName extracts the lowercased element name (with a leading '/' for a close
// tag) from a `<...>` span.
func tagName(tag string) string {
	t := strings.TrimPrefix(tag, "<")
	t = strings.TrimSuffix(t, ">")
	t = strings.TrimSpace(t)
	end := len(t)
	for i, c := range t {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '/' && i > 0 {
			end = i
			break
		}
	}
	return strings.ToLower(t[:end])
}

// TestHTMLHasNoExternalReferences asserts the document is genuinely
// self-contained: it must open from file:// with no network access, which is
// also why there is nothing loadable for a crafted value to point at.
func TestHTMLHasNoExternalReferences(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.10.10.22", responder: "10.10.10.21", rport: 3306, proto: "tcp", class: "brute_force", classID: 3, score: 0.93, disagreement: true, offsetSec: 0},
		spec{flowID: 2, initiator: "10.10.10.22", responder: "10.10.10.21", rport: 22, proto: "tcp", class: "scan", classID: 1, score: 0.81, offsetSec: 1},
	)
	r := mustBuild(t, f.src, hostOpts("10.10.10.22"))
	out, err := r.HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	got := string(out)
	low := strings.ToLower(got)

	// No loadable external resource of any kind.
	for _, bad := range []string{
		"http://", "https://", "//cdn", "<script", "<link", "<img", "<iframe",
		"<object", "<embed", "@import", "url(", "srcset", "integrity=",
		"data:", "<base", "<form", "<audio", "<video", "<track", "<source",
	} {
		if strings.Contains(low, bad) {
			t.Fatalf("HTML report contains an external/loadable reference %q\n%s", bad, context(got, bad))
		}
	}

	// Exactly one inline stylesheet, and it is inline.
	if n := strings.Count(low, "<style"); n != 1 {
		t.Fatalf("want exactly one inline <style>, got %d", n)
	}
	// A real document, not a fragment.
	for _, want := range []string{"<!doctype html>", "@media print", "</html>"} {
		if !strings.Contains(low, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	// The dark palette and the print override are both present.
	if !strings.Contains(got, "--accent:#35c1d6") {
		t.Fatal("project palette missing from the inline style")
	}
}

// TestHTMLCSSWidthsAreWellFormed guards the one CSS interpolation context in
// the document. html/template's cssValueFilter replaces anything it cannot
// vouch for with ZgotmplZ; if a bar width ever stopped being a plain Go-side
// percentage, this test catches it.
func TestHTMLCSSWidthsAreWellFormed(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.10.10.22", responder: "10.10.10.21", rport: 3306, proto: "tcp", class: "brute_force", classID: 3, score: 0.93},
		spec{flowID: 2, initiator: "10.10.10.22", responder: "10.10.10.21", rport: 22, proto: "tcp", class: "scan", classID: 1, score: 0.81},
	)
	r := mustBuild(t, f.src, hostOpts("10.10.10.22"))
	out, err := r.HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	got := string(out)
	if strings.Contains(got, "ZgotmplZ") {
		t.Fatalf("html/template rejected an interpolated value:\n%s", context(got, "ZgotmplZ"))
	}
	widths := regexp.MustCompile(`style="width:([^"]*)"`).FindAllStringSubmatch(got, -1)
	if len(widths) == 0 {
		t.Fatal("no bar widths rendered")
	}
	ok := regexp.MustCompile(`^[0-9]+\.[0-9]%$`)
	for _, w := range widths {
		if !ok.MatchString(w[1]) {
			t.Fatalf("bar width %q is not a plain percentage", w[1])
		}
	}
}

// TestHTMLCarriesTheHonestyNotes asserts the caveats are in the rendered
// document, not just in the JSON — a reader who only ever sees the HTML must
// still be told what the report does not know.
func TestHTMLCarriesTheHonestyNotes(t *testing.T) {
	// A tiny classification ring plus a tiny key cap trips both a store
	// eviction and a top-N prune.
	specs := make([]spec, 0, 20)
	for i := 0; i < 20; i++ {
		specs = append(specs, spec{
			flowID: uint64(i + 1), initiator: "10.10.10.22", responder: "10.10.10.21",
			rport: uint16(2000 + i), proto: "tcp", class: "scan", classID: 1,
			score: 0.8, offsetSec: i,
		})
	}
	f := newFixture(t, insight.Options{MaxKeys: 4}, specs...)
	opt := hostOpts("10.10.10.22")
	opt.MaxFlows = 3
	r := mustBuild(t, f.src, opt)

	out, err := r.HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	got := string(out)

	for _, want := range []string{
		// Phase 7 unavailability, stated not implied.
		"NOT AVAILABLE IN THIS BUILD (Phase 7)",
		"Behavioural baseline comparison is not available in this build",
		"No anomaly model scored this traffic",
		// Partial view.
		"PARTIAL VIEW",
		"partial view — see caveats",
		// Truncation, with the limit named.
		"TRUNCATED",
		// The coverage table itself.
		"Coverage and limits",
		"What this report does not tell you",
		// The build stamp.
		"report schema " + SchemaID,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered HTML is missing %q", want)
		}
	}
	// The note codes are machine-readable in the HTML too.
	for _, code := range []string{NoteBaselineUnavailable, NotePartialTopNPruned, NoteFlowsTruncated} {
		if !strings.Contains(got, code) {
			t.Fatalf("note code %q missing from the HTML", code)
		}
	}
}

// TestHTMLRendersAnEmptyReport makes sure the "nothing to show" path says so
// rather than producing a document that reads as an all-clear.
func TestHTMLRendersAnEmptyReport(t *testing.T) {
	r, err := Build(Sources{}, rangeOpts())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	out, err := r.HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		"No verdicts in scope.",
		"This is an absence of retained\n  data, not a statement that the window was quiet.",
		"NOT AVAILABLE IN THIS BUILD (Phase 7)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("empty report missing %q", want)
		}
	}
}

// context returns a window of the output around the first occurrence of needle,
// so a failure message shows what actually happened.
func context(s, needle string) string {
	i := strings.Index(strings.ToLower(s), strings.ToLower(needle))
	if i < 0 {
		return ""
	}
	lo := max(i-160, 0)
	hi := min(i+len(needle)+160, len(s))
	return s[lo:hi]
}
