// Package transformer provides value transformers for value wrappers.
package transformer

import "errors"

// ErrImpossibleOperation is raised when the callee tried to execute an
// irreversible operation.
var ErrImpossibleOperation = errors.New("impossible transformer operation request")

// Transformer describes value transformater contract.
type Transformer interface {
	Encode(src []byte) ([]byte, error)
	Decode(from []byte) ([]byte, error)
}
