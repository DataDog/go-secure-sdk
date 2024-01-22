package envelope

// Option describes the enveleope wrapping option function.
type Option func(*options)

type options struct {
	timestamp uint64
}

// WithTimestamp sets the signature timestamp.
func WithTimestamp(r uint64) Option {
	return func(o *options) {
		o.timestamp = r
	}
}
