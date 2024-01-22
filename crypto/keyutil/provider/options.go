package provider

import "fmt"

// Option describes key provider builder option
type Option func(*defaultProvider) error

// WithEntry describes the associated with a key alias and a key factory.
func WithEntry(alias KeyAlias, kf KeyFactory) Option {
	return func(kp *defaultProvider) error {
		if err := kp.Register(alias, kf); err != nil {
			return fmt.Errorf("unable to register key %q: %w", alias, err)
		}

		return nil
	}
}
