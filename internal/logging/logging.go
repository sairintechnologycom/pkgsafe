// Package logging provides a small leveled, structured logger built on
// log/slog. It replaces ad-hoc fmt.Fprintln(os.Stderr, ...) so operators can
// control verbosity and machine-parse logs for SOC/aggregation.
//
// Configuration (environment):
//
//	PKGSAFE_LOG_LEVEL  = debug | info | warn | error   (default: warn)
//	PKGSAFE_LOG_FORMAT = text | json                   (default: text)
//
// The default level is warn so normal CLI output stays clean; set
// PKGSAFE_LOG_LEVEL=info or debug for operational/troubleshooting detail.
package logging

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	once   sync.Once
	logger *slog.Logger
)

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "error":
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}

func build() *slog.Logger {
	level := parseLevel(os.Getenv("PKGSAFE_LOG_LEVEL"))
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PKGSAFE_LOG_FORMAT")), "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

// L returns the process logger, initialized from the environment on first use.
func L() *slog.Logger {
	once.Do(func() { logger = build() })
	return logger
}

// SetLogger overrides the process logger (useful in tests).
func SetLogger(l *slog.Logger) {
	once.Do(func() {}) // mark initialized so L() won't rebuild
	logger = l
}

func Debug(msg string, args ...any) { L().Debug(msg, args...) }
func Info(msg string, args ...any)  { L().Info(msg, args...) }
func Warn(msg string, args ...any)  { L().Warn(msg, args...) }
func Error(msg string, args ...any) { L().Error(msg, args...) }
