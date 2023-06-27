// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package log

var factory Factory = &noop{}

// SetFactory sets the static logger factory.
func SetFactory(f Factory) {
	factory = f
}

// New returns a new logger instance from the static factory.
func New() Logger {
	return factory.New()
}

// Level returns a new logger instance from the factory setting its log level to the value supplied.
func Level(lvl LoggerLevel) Logger {
	return factory.New().Level(lvl)
}

// Field returns a new logger instance from the factory setting a field value as supplied.
func Field(k string, v any) Logger {
	return factory.New().Field(k, v)
}

// Fields returns a new logger instance from the factory setting field values as supplied.
func Fields(data map[string]any) Logger {
	return factory.New().Fields(data)
}

// Error returns a new logger instance from the factory setting the error as supplied.
func Error(err error) Logger {
	return factory.New().Error(err)
}
