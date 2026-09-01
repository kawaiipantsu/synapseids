package obs

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"strings"
)

// LogFormats and LogLevels are the accepted config values (config.Logging
// validates against these).
var (
	LogFormats = []string{"text", "json"}
	LogLevels  = []string{"debug", "info", "warn", "error"}
)

// Logger bundles the process logger with a live level knob, so config hot-reload
// (issue #59) can raise or lower verbosity without a restart.
type Logger struct {
	*slog.Logger
	level *slog.LevelVar
}

// SetLevel changes the active level. The string is validated the same way the
// config loader does; an unknown value is a no-op and returns an error.
func (l *Logger) SetLevel(name string) error {
	lvl, err := parseLevel(name)
	if err != nil {
		return err
	}
	l.level.Set(lvl)
	return nil
}

// Level reports the current level as a lower-case string.
func (l *Logger) Level() string {
	return strings.ToLower(l.level.Level().String())
}

// SetupLogging builds the process logger from the config values and installs it
// everywhere output can originate:
//
//   - slog.SetDefault, for code using the structured API;
//   - log.SetOutput / SetFlags, so the many packages that still take an injected
//     `func(string, ...any)` backed by the standard log package emit through the
//     same handler at info level, with no timestamp/prefix of their own (the
//     handler adds a structured time).
//
// format is "text" (default, human-readable key=value) or "json". level is one
// of debug|info|warn|error. Both are assumed already validated by config; an
// unknown value falls back to the default and is reported in the returned error
// for the caller to log-and-continue.
func SetupLogging(w io.Writer, format, level string) (*Logger, error) {
	var ferr, lerr error

	lvlVar := new(slog.LevelVar)
	if lvl, err := parseLevel(level); err != nil {
		lerr = err
		lvlVar.Set(slog.LevelInfo)
	} else {
		lvlVar.Set(lvl)
	}

	opts := &slog.HandlerOptions{Level: lvlVar}
	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		ferr = fmt.Errorf("unknown log format %q (want one of %v)", format, LogFormats)
		h = slog.NewTextHandler(w, opts)
	}

	logger := slog.New(h)
	slog.SetDefault(logger)

	// Bridge the standard log package: strip its own timestamp/prefix and route
	// every line through slog at info level so an injected log.Printf still lands
	// in the structured stream.
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(bridgeWriter{logger})

	return &Logger{Logger: logger, level: lvlVar}, firstErr(ferr, lerr)
}

func parseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q (want one of %v)", name, LogLevels)
	}
}

// bridgeWriter turns a line written to the standard log package into one slog
// record. A leading "WARNING: " or "ERROR: " (the convention this codebase
// already uses for a few lines) is promoted to the matching level so the
// migration does not silently downgrade them.
type bridgeWriter struct{ l *slog.Logger }

func (b bridgeWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	switch {
	case strings.HasPrefix(msg, "WARNING: "):
		b.l.Warn(strings.TrimPrefix(msg, "WARNING: "))
	case strings.HasPrefix(msg, "ERROR: "):
		b.l.Error(strings.TrimPrefix(msg, "ERROR: "))
	default:
		b.l.Info(msg)
	}
	return len(p), nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
