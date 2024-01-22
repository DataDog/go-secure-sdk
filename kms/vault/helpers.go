package vault

import (
	"strings"
)

// SanitizePath removes any leading or trailing things from a "path".
func sanitizePath(s string) string {
	return ensureNoTrailingSlash(ensureNoLeadingSlash(strings.TrimSpace(s)))
}

// ensureNoTrailingSlash ensures the given string has a trailing slash.
func ensureNoTrailingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// ensureNoLeadingSlash ensures the given string has a trailing slash.
func ensureNoLeadingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}
