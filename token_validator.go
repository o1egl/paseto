package paseto

import (
	"errors"
	"fmt"
	"time"
)

// Validator defines JSONToken validator function
type Validator func(token *JSONToken) error

// ForAudience validates JSONToken audience
func ForAudience(audience string) Validator {
	return func(token *JSONToken) error {
		if token.Audience != audience {
			return fmt.Errorf(`token was not intended for "%s" audience`, audience)
		}
		return nil
	}
}

// IdentifiedBy validates JSONToken JTI
func IdentifiedBy(jti string) Validator {
	return func(token *JSONToken) error {
		if token.Jti != jti {
			return fmt.Errorf(`token was expected to be identified by "%s"`, jti)
		}
		return nil
	}
}

// IssuedBy validates JSONToken issuer
func IssuedBy(issuer string) Validator {
	return func(token *JSONToken) error {
		if token.Issuer != issuer {
			return fmt.Errorf(`token was not issued by "%s"`, issuer)
		}
		return nil
	}
}

// Subject validates JSONToken subject
func Subject(subject string) Validator {
	return func(token *JSONToken) error {
		if token.Subject != subject {
			return fmt.Errorf(`token was not related to subject "%s"`, subject)
		}
		return nil
	}
}

// ValidAt validates if token valid at specified time based on IssuedAt, NotBefore and Expiration fields
func ValidAt(t time.Time) Validator {
	return func(token *JSONToken) error {
		if !token.IssuedAt.IsZero() && t.Before(token.IssuedAt) {
			return errors.New("token was issued in the future")
		}
		if !token.NotBefore.IsZero() && t.Before(token.NotBefore) {
			return errors.New("token cannot be used yet")
		}
		if !token.Expiration.IsZero() && t.After(token.Expiration) {
			return errors.New("token has expired")
		}
		return nil
	}
}
