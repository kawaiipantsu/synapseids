package config

import (
	"fmt"
	"strconv"
	"strings"
)

// A deliberately small YAML reader for the config file (issue #54, PROJECT.md
// §23). The stack is stdlib-only (CLAUDE.md: zero third-party Go dependencies),
// so this is hand-rolled rather than `gopkg.in/yaml.v3`.
//
// It parses YAML into the same JSON-compatible tree the JSON decoder consumes,
// so every bit of type coercion, `DisallowUnknownFields` and `validate()` is
// shared — the only new code is turning indentation into nesting.
//
// SUPPORTED: block mappings (`key: value`), block sequences (`- item`, where an
// item is a scalar or a mapping), plain and single/double-quoted scalars,
// `#` comments, blank lines, one leading `---`. Indentation is spaces; the step
// is inferred from the first indented line.
//
// NOT SUPPORTED, and rejected with a line-numbered error rather than
// mis-parsed: tabs in indentation, flow style (`{...}` / `[...]`), anchors and
// aliases (`&` / `*`), tags (`!`), block scalars (`|` / `>`), multi-line plain
// scalars, multiple documents, and `%` directives. The config file has never
// needed any of them; if it ever does, this is the place to grow.
func parseYAML(src []byte) (map[string]any, error) {
	p := &yamlParser{lines: splitYAMLLines(string(src))}
	root := map[string]any{}
	if err := p.parseMapping(root, -1); err != nil {
		return nil, err
	}
	if p.i < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected content at indent %d", p.lines[p.i].n, p.lines[p.i].indent)
	}
	return root, nil
}

type yamlLine struct {
	n      int    // 1-based source line number
	indent int    // leading spaces
	text   string // trimmed of indent and trailing whitespace, comments stripped
	tabbed bool   // the leading whitespace contained a tab
}

type yamlParser struct {
	lines []yamlLine
	i     int
}

// splitYAMLLines drops blanks, comment-only lines and a leading `---`, strips a
// trailing `# comment` from a value line (only when the `#` is preceded by
// whitespace or at column 0, so a `#` inside a value is kept), and records the
// indent of each surviving line.
func splitYAMLLines(s string) []yamlLine {
	var out []yamlLine
	for i, raw := range strings.Split(s, "\n") {
		n := i + 1
		line := strings.TrimRight(raw, " \t\r")
		if line == "" {
			continue
		}
		lead := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		tabbed := strings.Contains(lead, "\t")
		indent := len(line) - len(strings.TrimLeft(line, " "))
		body := strings.TrimLeft(line, " \t")
		if body == "---" || body == "..." {
			continue
		}
		if strings.HasPrefix(body, "#") {
			continue
		}
		body = stripTrailingComment(body)
		body = strings.TrimRight(body, " \t")
		if body == "" {
			continue
		}
		out = append(out, yamlLine{n: n, indent: indent, text: body, tabbed: tabbed})
	}
	return out
}

// stripTrailingComment removes a ` #...` comment, but not a `#` that is part of
// a quoted string or is not preceded by a space.
func stripTrailingComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

// parseMapping fills dst with the key/value pairs whose indent is exactly one
// step deeper than parentIndent, recursing for nested structures.
func (p *yamlParser) parseMapping(dst map[string]any, parentIndent int) error {
	var childIndent = -1
	for p.i < len(p.lines) {
		ln := p.lines[p.i]
		if ln.tabbed {
			return fmt.Errorf("line %d: tab in indentation — YAML indentation must be spaces", ln.n)
		}
		if ln.indent <= parentIndent {
			return nil // belongs to an ancestor
		}
		if childIndent == -1 {
			childIndent = ln.indent
		}
		if ln.indent != childIndent {
			return fmt.Errorf("line %d: inconsistent indentation (expected %d spaces, got %d)", ln.n, childIndent, ln.indent)
		}
		if strings.HasPrefix(ln.text, "- ") || ln.text == "-" {
			return fmt.Errorf("line %d: a sequence item ('- ') where a `key:` mapping was expected", ln.n)
		}

		key, rest, ok := splitKey(ln.text)
		if !ok {
			return fmt.Errorf("line %d: expected `key: value`, got %q", ln.n, ln.text)
		}
		if _, dup := dst[key]; dup {
			return fmt.Errorf("line %d: duplicate key %q", ln.n, key)
		}
		p.i++

		if rest != "" {
			v, err := scalar(rest, ln.n)
			if err != nil {
				return err
			}
			dst[key] = v
			continue
		}
		// No inline value: a nested mapping or sequence at deeper indent, or null.
		if p.i >= len(p.lines) || p.lines[p.i].indent <= childIndent {
			dst[key] = nil
			continue
		}
		if strings.HasPrefix(p.lines[p.i].text, "- ") || p.lines[p.i].text == "-" {
			seq, err := p.parseSequence(childIndent)
			if err != nil {
				return err
			}
			dst[key] = seq
			continue
		}
		sub := map[string]any{}
		if err := p.parseMapping(sub, childIndent); err != nil {
			return err
		}
		dst[key] = sub
	}
	return nil
}

// parseSequence reads `- ` items whose indent is deeper than parentIndent. An
// item is a scalar, or a mapping when the item text is itself `key: value`.
func (p *yamlParser) parseSequence(parentIndent int) ([]any, error) {
	var out []any
	var itemIndent = -1
	for p.i < len(p.lines) {
		ln := p.lines[p.i]
		if ln.tabbed {
			return nil, fmt.Errorf("line %d: tab in indentation — YAML indentation must be spaces", ln.n)
		}
		if ln.indent <= parentIndent {
			return out, nil
		}
		if itemIndent == -1 {
			itemIndent = ln.indent
		}
		if ln.indent != itemIndent {
			return nil, fmt.Errorf("line %d: inconsistent sequence indentation", ln.n)
		}
		if !strings.HasPrefix(ln.text, "- ") && ln.text != "-" {
			return nil, fmt.Errorf("line %d: expected a sequence item ('- '), got %q", ln.n, ln.text)
		}
		body := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))

		if body == "" {
			return nil, fmt.Errorf("line %d: empty sequence item", ln.n)
		}
		if key, rest, ok := splitKey(body); ok {
			// A mapping item: this first pair sits on the `- ` line; any further
			// pairs are indented under the dash by the width of "- ".
			m := map[string]any{}
			if rest != "" {
				v, err := scalar(rest, ln.n)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			p.i++
			// Continuation pairs of this same item: deeper than itemIndent.
			if p.i < len(p.lines) && p.lines[p.i].indent > itemIndent &&
				!strings.HasPrefix(p.lines[p.i].text, "- ") {
				if err := p.parseMapping(m, itemIndent); err != nil {
					return nil, err
				}
			}
			if rest == "" && len(m) == 0 {
				return nil, fmt.Errorf("line %d: sequence item %q has no value", ln.n, key)
			}
			out = append(out, m)
			continue
		}
		// A scalar item.
		v, err := scalar(body, ln.n)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.i++
	}
	return out, nil
}

// splitKey splits "key: value" (or "key:") on the first ": " / trailing ":".
// The key is unquoted and must be a plain scalar.
func splitKey(s string) (key, rest string, ok bool) {
	if strings.HasSuffix(s, ":") {
		k := strings.TrimSpace(s[:len(s)-1])
		if k == "" || strings.ContainsAny(k, "{}[]&*!|>#") {
			return "", "", false
		}
		return unquoteKey(k), "", true
	}
	idx := strings.Index(s, ": ")
	if idx < 0 {
		return "", "", false
	}
	k := strings.TrimSpace(s[:idx])
	if k == "" {
		return "", "", false
	}
	return unquoteKey(k), strings.TrimSpace(s[idx+2:]), true
}

func unquoteKey(k string) string {
	if len(k) >= 2 && (k[0] == '"' || k[0] == '\'') && k[len(k)-1] == k[0] {
		return k[1 : len(k)-1]
	}
	return k
}

// scalar converts one value token to a JSON-compatible Go value, rejecting the
// YAML features this reader does not implement.
func scalar(s string, lineNo int) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return nil, nil
	case s == "[]":
		return []any{}, nil // an empty sequence is the one bit of flow style allowed
	case s == "{}":
		return map[string]any{}, nil
	case s[0] == '&' || s[0] == '*':
		return nil, fmt.Errorf("line %d: anchors and aliases (%q) are not supported", lineNo, s)
	case s[0] == '!':
		return nil, fmt.Errorf("line %d: tags (%q) are not supported", lineNo, s)
	case s[0] == '{' || s[0] == '[':
		return nil, fmt.Errorf("line %d: flow style (%q) is not supported — use block style (an empty [] or {} is fine)", lineNo, s)
	case s == "|" || s == ">" || strings.HasPrefix(s, "| ") || strings.HasPrefix(s, "> "):
		return nil, fmt.Errorf("line %d: block scalars ('|', '>') are not supported", lineNo)
	}

	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return unescapeDouble(s[1 : len(s)-1]), nil
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}

	switch strings.ToLower(s) {
	case "null", "~":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	return s, nil // a plain string (includes durations like "30s")
}

func unescapeDouble(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
