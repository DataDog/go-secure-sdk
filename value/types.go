package value

// AsRedactedString wraps the given string value into a redacted value container.
func AsRedactedString(in string) RedactedString {
	return RedactedString{
		Redacted: AsRedacted(in),
	}
}

// RedactedString wraps a redactable string to offer unmarshalling feature.
type RedactedString struct {
	Redacted[string]
}

// UnmarshalText implements encoding.TextUnmarshaler interface for RedactedString.
func (rs *RedactedString) UnmarshalText(text []byte) error {
	rs.Redacted = AsRedacted(string(text))
	return nil
}
