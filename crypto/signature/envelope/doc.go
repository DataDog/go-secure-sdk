// Package envelope provides Envelope signature scheme.
//
// To prevent caninicalization complexity, the envelope encryption bundles the
// payload with the signature so that the Verifier should have to use the payload
// as protected content.
package envelope
