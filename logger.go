package main

import (
	"log"
	"strings"
)

// LogLevel represents logging verbosity level.
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// Logger wraps standard log with level filtering.
type Logger struct {
	level LogLevel
}

var logger *Logger

// InitLogger initializes the global logger with specified level.
func InitLogger(level string) {
	var logLevel LogLevel
	switch strings.ToLower(level) {
	case "debug":
		logLevel = LogLevelDebug
	case "info":
		logLevel = LogLevelInfo
	case "warn", "warning":
		logLevel = LogLevelWarn
	case "error":
		logLevel = LogLevelError
	case "silent", "none":
		logLevel = LogLevelSilent
	default:
		logLevel = LogLevelInfo
	}
	logger = &Logger{level: logLevel}
}

// Debug logs debug-level messages.
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level >= LogLevelDebug {
		log.Printf(format, v...)
	}
}

// Info logs info-level messages.
func (l *Logger) Info(format string, v ...interface{}) {
	if l.level >= LogLevelInfo {
		log.Printf(format, v...)
	}
}

// Warn logs warning-level messages.
func (l *Logger) Warn(format string, v ...interface{}) {
	if l.level >= LogLevelWarn {
		log.Printf(format, v...)
	}
}

// Error logs error-level messages.
func (l *Logger) Error(format string, v ...interface{}) {
	if l.level >= LogLevelError {
		log.Printf(format, v...)
	}
}

// Fatal logs fatal error and exits (always shown).
func (l *Logger) Fatal(v ...interface{}) {
	log.Fatal(v...)
}

// Fatalf logs fatal error with format and exits (always shown).
func (l *Logger) Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

// Printf is a convenience method that logs at info level.
func (l *Logger) Printf(format string, v ...interface{}) {
	l.Info(format, v...)
}
