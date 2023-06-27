// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package log provides a high level logger abstraction.
package log

// LoggerLevel defines level markers for log entries.
type LoggerLevel int

const (
	// UnsetLevel should not be output by logger implementation.
	UnsetLevel = iota - 2
	// DebugLevel marks detailed output for design purposes.
	DebugLevel
	// InfoLevel is the default log output marker.
	InfoLevel
	// ErrorLevel marks an error output.
	ErrorLevel
)

// Factory defines a utility to create new loggers and set the log level threshold.
type Factory interface {
	// New creates a new logger.
	New() Logger
}

// Logger describes logger feature interface.
type Logger interface {
	Level(lvl LoggerLevel) Logger
	Field(k string, v any) Logger
	Fields(data map[string]any) Logger
	Error(err error) Logger
	Message(msg string)
	Messagef(format string, v ...any)
}
