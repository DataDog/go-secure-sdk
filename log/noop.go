// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package log

// implements a no-operation logger so that the logger interface can be used
// out of the box without providing an actual implementation
type noop struct{}

var (
	_ Factory = (*noop)(nil)
	_ Logger  = (*noop)(nil)
)

func (n *noop) New() Logger {
	return &noop{}
}

func (n *noop) Threshold(lvl LoggerLevel) {
}

func (n *noop) Level(lvl LoggerLevel) Logger {
	return n
}

func (n *noop) Field(k string, v interface{}) Logger {
	return n
}

func (n *noop) Fields(data map[string]interface{}) Logger {
	return n
}

func (n *noop) Error(err error) Logger {
	return n
}

func (n *noop) Message(_ string) {
}

func (n *noop) Messagef(_ string, _ ...any) {
}
