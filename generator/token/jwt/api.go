// Package jwt provides external signature mechanism for JWT token signature process.
package jwt

import (
	jwt "github.com/golang-jwt/jwt/v4"
)

//go:generate mockgen -destination test/mock/signer.gen.go -package mock github.com/DataDog/go-secure-sdk/generator/token/jwt Signer

// Signer represents the JWT Token signer contract.
type Signer interface {
	jwt.SigningMethod
	KeyID() string
}
