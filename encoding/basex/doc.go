// Package basex provides fast base encoding / decoding of any given alphabet.
//
// It has been copied from github.com/eknkc/basex
// Added some preconditions to prevent simple errors.
//
// This library is meant to be used for a given static alphabet, if you are
// planning to use common encoding such as Base64, please ensure to use the
// dedicated library to support additionnal encoding features (padding, etc.).
package basex
