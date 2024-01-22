package canonicalization

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	maxPieceSize  = 64 * 1024 // 64Kb
	maxPieceCount = 25
)

var (
	// ErrPieceTooLarge is raised when one piece size is larger than the accepted size.
	ErrPieceTooLarge = errors.New("at least one piece is too large")
	// ErrTooManyPieces is raised when the pieces count is larger than the accepted count.
	ErrTooManyPieces = errors.New("too many pieces provided")
)

// PreAuthenticationEncoding implements pre-authenticated-encoding primitive to
// encode before MAC or HASH values.
// It acts as a normalized canonicalization process.
//
// Canonicalization helps avoid confusion when you have a few separate pieces of
// data to hash or encrypt with a single pass. For example, you might want to hash
// or sign a string like `userId=1234&userName=megan`.
//
// But the user could change their `userName` to `megan&userRole=admin` and
// unexpectedly escalate their privileges when the decoder can't tell which parts
// of the data are controlled by the user vs. the code.
//
// Use canonicalization to separate each piece of data so there's no possibility
// of confusing the separate pieces.
//
// If you are interested in more knowledge about canonicalization attacks =>
// https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/
//
// This canonicalization implementation comes from the PASETO specification
// described in the following specification.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
//
// The canonicalization process accepts :
// * 25 piece count maximum or raise an ErrTooManyPiece error if above the threshold
// * 64Kb per piece maximum or raise an ErrPieceTooLarge error if above the threshold
func PreAuthenticationEncoding(pieces ...[]byte) ([]byte, error) {
	// Check arguments
	if len(pieces) == 0 {
		return nil, nil
	}
	if len(pieces) > maxPieceCount {
		return nil, fmt.Errorf("unable to prepare canonical form: %w", ErrTooManyPieces)
	}

	// Precompute length to allocate the buffer
	// PieceCount (8B) || ( PieceLen (8B) || Piece (*B) )*
	bufLen := 8
	for i := range pieces {
		if len(pieces[i]) > maxPieceSize {
			return nil, fmt.Errorf("unable to prepare canonical form: %w", ErrPieceTooLarge)
		}
		bufLen += 8 + len(pieces[i])
	}

	// Pre-allocate the buffer
	output := make([]byte, bufLen)

	// Encode piece count
	binary.LittleEndian.PutUint64(output, uint64(len(pieces)))

	offset := 8
	// For each element
	for i := range pieces {
		// Encode size
		binary.LittleEndian.PutUint64(output[offset:], uint64(len(pieces[i])))
		offset += 8

		// Encode data
		copy(output[offset:], pieces[i])
		offset += len(pieces[i])
	}

	// No error
	return output, nil
}
