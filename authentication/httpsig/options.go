package httpsig

// VerifyOption defines optional parameters for Verify operation.
type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	maxBodySize uint64
}

// WithMaxBodySize sets the body size limit.
// Default to 100MB.
func WithMaxBodySize(value uint64) VerifyOption {
	return func(vo *verifyOptions) {
		vo.maxBodySize = value
	}
}
