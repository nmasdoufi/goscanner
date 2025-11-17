package logging

import (
	"fmt"
	"io"
	"log"
	"os"
)

// Level describes severity of log message.
type Level int

const (
	// LevelInfo is default log level.
	LevelInfo Level = iota
	// LevelDebug enables verbose output.
	LevelDebug
)

// ParseLevel converts string to Level.
func ParseLevel(v string) Level {
	switch v {
	case "debug":
		return LevelDebug
	default:
		return LevelInfo
	}
}

// Logger is a thin wrapper around log.Logger with levels.
type Logger struct {
	logger *log.Logger
	level  Level
}

// New creates a configured logger.
func New(path string, level Level) (*Logger, error) {
	var output io.Writer = os.Stdout
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		output = f
	}
	return &Logger{logger: log.New(output, "goscanner ", log.LstdFlags), level: level}, nil
}

func (l *Logger) logf(lvl Level, format string, args ...interface{}) {
	if l == nil {
		return
	}
	if lvl > l.level {
		return
	}
	prefix := "INFO"
	if lvl == LevelDebug {
		prefix = "DEBUG"
	}
	l.logger.Printf("[%s] %s", prefix, fmt.Sprintf(format, args...))
}

// Infof logs informational messages.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logf(LevelInfo, format, args...)
}

// Debugf logs verbose diagnostic messages.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logf(LevelDebug, format, args...)
}

// Errorf logs errors and warnings.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logf(LevelInfo, format, args...)
}

// Printf keeps compatibility with standard log API.
func (l *Logger) Printf(format string, args ...interface{}) {
	l.Infof(format, args...)
}
