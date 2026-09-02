package main

import (
	"fmt"
	"log"
	"strings"
)

// logVerbosity controls how much synapse-sensor writes to its log. It is set
// once from --log-level (which the OPNsense plugin drives from the "Log level"
// dropdown under SynapseIDS > General) before any capture starts, and never
// changes afterwards, so the gate below needs no synchronisation.
type logVerbosity int

const (
	// logErrorsOnly writes only warnings and failures — the lines an operator
	// must not miss (an unverified transport, a missing token, a dial failure).
	logErrorsOnly logVerbosity = iota
	// logNormal adds the lifecycle: the sensor identity, the send mode, the
	// transport posture, "stopped". This is the default and matches the output
	// every release before --log-level produced.
	logNormal
	// logVerbose adds per-connection detail: each dial, each handshake, each
	// reconnect delay.
	logVerbose
)

// currentLogVerbosity is the process-wide level. Default is logNormal so a
// sensor started without --log-level logs exactly as it did before.
var currentLogVerbosity = logNormal

// logLevelValues lists the accepted --log-level strings, for the flag help and
// for validation error messages. Kept in sync with parseLogVerbosity.
var logLevelValues = []string{"errors", "normal", "verbose"}

// parseLogVerbosity maps a --log-level value onto a logVerbosity. An empty
// string keeps the default; "error"/"debug" are accepted as friendly aliases.
func parseLogVerbosity(s string) (logVerbosity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "normal":
		return logNormal, nil
	case "errors", "error":
		return logErrorsOnly, nil
	case "verbose", "debug":
		return logVerbose, nil
	default:
		return logNormal, fmt.Errorf("unknown --log-level %q (want %s)", s, strings.Join(logLevelValues, ", "))
	}
}

// logErrorf writes unconditionally: warnings and failures are never suppressed,
// however quiet the operator asked the log to be.
func logErrorf(format string, a ...any) { log.Printf(format, a...) }

// logInfof writes at logNormal and above — the lifecycle lines.
func logInfof(format string, a ...any) {
	if currentLogVerbosity >= logNormal {
		log.Printf(format, a...)
	}
}

// logVerbosef writes only at logVerbose — per-connection chatter.
func logVerbosef(format string, a ...any) {
	if currentLogVerbosity >= logVerbose {
		log.Printf(format, a...)
	}
}

// infoLogf returns logInfof as a func value, or a no-op at logErrorsOnly, for
// the capture adapters that take a Logf callback. Their output is lifecycle
// detail ("serving on ...", "source is ..."), so it follows the logNormal gate.
func infoLogf() func(string, ...any) {
	if currentLogVerbosity >= logNormal {
		return log.Printf
	}
	return func(string, ...any) {}
}
