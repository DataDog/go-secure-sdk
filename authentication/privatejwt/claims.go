package privatejwt

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrExpiredAssertion is raised when the expiration is reached.
var ErrExpiredAssertion = errors.New("the assertion is expired")

// Claims describes the assertion properties.
type Claims struct {
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  string    `json:"aud"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
}

// Validate the current claims coherence.
func (c *Claims) Validate(clientID, audience string, now time.Time) error {
	// Validate string fields
	switch {
	case c.Issuer != clientID:
		return fmt.Errorf("issuer must not be %q", c.Issuer)
	case c.Subject != clientID:
		return fmt.Errorf("subject must not be %q", c.Subject)
	case c.Audience != audience:
		return fmt.Errorf("audience must not be %q", c.Audience)
	case strings.TrimSpace(c.JTI) == "":
		return errors.New("jti must not be blank")
	case len(strings.TrimSpace(c.JTI)) != jtiLength:
		return errors.New("the assertion has an invalid JTI length")
	case c.IssuedAt.After(c.ExpiresAt):
		return errors.New("the issuance date is after the expiration")
	case c.IssuedAt.Add(maxExpiration).Before(c.ExpiresAt):
		return errors.New("the assertion has an expiration too far into the future")
	case now.After(c.ExpiresAt.Add(clockSkewTolerance)): // now > exp + clockskew
		return ErrExpiredAssertion
	case now.Add(clockSkewTolerance).Before(c.IssuedAt): // now + clockskew < iat
		return errors.New("the assertion is not yet valid")
	}

	return nil
}
