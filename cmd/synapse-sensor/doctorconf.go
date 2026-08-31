package main

// Parsing of the configd-rendered /usr/local/etc/synapseids/sensor.conf.
//
// That file is a POSIX-sh fragment which the rc.d script sources **as root**, so
// the parser here is deliberately strict rather than forgiving: it accepts only
// `name=value` with an optionally quoted scalar value, and it rejects anything
// that looks like command substitution or a variable expansion. If the configd
// template ever produced such a thing it would be a template-escaping bug with
// root consequences, and `doctor` should say so loudly instead of shrugging.
//
// No build tag: the parser is pure string handling, so it is tested on Linux and
// runs unchanged on FreeBSD.

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// sensorConf is the set of shell variables the sensor.conf template renders.
type sensorConf struct {
	vars map[string]string
	// order preserves the order variables appeared, for reproducible output.
	order []string
}

func (c sensorConf) get(name string) string { return c.vars[name] }

// enabledWord is the raw rcvar value, for display.
func (c sensorConf) enabledWord() string {
	if v := c.get("synapseids_sensor_enable"); v != "" {
		return v
	}
	return "NO"
}

func (c sensorConf) enabled() bool {
	switch strings.ToUpper(c.enabledWord()) {
	case "YES", "TRUE", "ON", "1":
		return true
	}
	return false
}

// args is the rendered flag list, split into words.
func (c sensorConf) args() []string { return splitShellWords(c.get("synapseids_sensor_args")) }

// transport reports "connect" or "listen" from the rendered flags.
func (c sensorConf) transport() string {
	args := c.args()
	if flagValue(args, "--connect") != "" {
		return "connect"
	}
	return "listen"
}

// parseSensorConf reads the rendered shell fragment.
func parseSensorConf(r io.Reader) (sensorConf, error) {
	conf := sensorConf{vars: map[string]string{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name, value, ok := strings.Cut(text, "=")
		if !ok {
			return conf, fmt.Errorf("line %d is not name=value: %q", line, truncate(text))
		}
		name = strings.TrimSpace(name)
		if !validShellName(name) {
			return conf, fmt.Errorf("line %d: %q is not a valid shell variable name", line, truncate(name))
		}
		value, err := unquoteShellValue(strings.TrimSpace(value))
		if err != nil {
			return conf, fmt.Errorf("line %d (%s): %w", line, name, err)
		}
		if _, seen := conf.vars[name]; !seen {
			conf.order = append(conf.order, name)
		}
		conf.vars[name] = value
	}
	if err := sc.Err(); err != nil {
		return conf, err
	}
	if len(conf.vars) == 0 {
		return conf, fmt.Errorf("no variables found; the template rendered nothing usable")
	}
	return conf, nil
}

func validShellName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || unicode.IsLetter(r) && r < unicode.MaxASCII {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// unquoteShellValue strips one layer of surrounding quotes and refuses any value
// that would be re-interpreted by the shell that sources this file.
func unquoteShellValue(v string) (string, error) {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			// A quoted value may legitimately contain the *other* quote character
			// and spaces; the template strips quotes from every interpolated
			// value, so an inner quote of the same kind cannot occur.
			inner := v[1 : len(v)-1]
			if strings.ContainsRune(inner, rune(v[0])) && v[0] == '"' {
				return "", fmt.Errorf("unbalanced double quotes in %q", truncate(v))
			}
			v = inner
		} else if strings.ContainsAny(v, "\"'") {
			return "", fmt.Errorf("unquoted value contains a quote character: %q", truncate(v))
		}
	}
	for _, bad := range []string{"$(", "${", "`", "$"} {
		if strings.Contains(v, bad) {
			return "", fmt.Errorf("value contains %q, which the shell sourcing this file would expand", bad)
		}
	}
	if strings.ContainsAny(v, ";|&\n\r") {
		return "", fmt.Errorf("value contains a shell metacharacter: %q", truncate(v))
	}
	return v, nil
}

// splitShellWords splits a rendered flag string into words, honouring the single
// quotes the template puts around values that may contain a space (--sensor-id,
// --location). It is not a general shell lexer and does not need to be: the
// template's sh() macro has already removed every quote character from the
// interpolated values, so the only quotes present are the ones it added itself.
func splitShellWords(s string) []string {
	var (
		words []string
		cur   strings.Builder
		quote rune
		open  bool
	)
	flush := func() {
		if open {
			words = append(words, cur.String())
			cur.Reset()
			open = false
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
			open = true
		case r == '\'' || r == '"':
			quote = r
			open = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			open = true
		}
	}
	flush()
	return words
}

// flagValue returns the value following name, or "" when the flag is absent.
// Both `--flag value` and `--flag=value` are recognised.
func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				return args[i+1]
			}
			return ""
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v
		}
	}
	return ""
}

// hasFlag reports whether a bare boolean flag is present.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || a == name+"=true" {
			return true
		}
	}
	return false
}

func truncate(s string) string {
	const max = 60
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
