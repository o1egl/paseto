package paseto

import (
	"errors"
	"fmt"
	"time"
)

// Validator defines a JSONToken validator function.
type Validator func(token *JSONToken) error

// ForAudience validates that the JSONToken audience has the specified value.
func ForAudience(audience string) Validator {
	return func(token *JSONToken) error {
		if token.Audience != audience {
			return fmt.Errorf(`token was not intended for "%s" audience`, audience)
		}
		return nil
	}
}

// IdentifiedBy validates that the JSONToken JTI has the specified value.
func IdentifiedBy(jti string) Validator {
	return func(token *JSONToken) error {
		if token.Jti != jti {
			return fmt.Errorf(`token was expected to be identified by "%s"`, jti)
		}
		return nil
	}
}

// IssuedBy validates that the JSONToken issuer has the specified value.
func IssuedBy(issuer string) Validator {
	return func(token *JSONToken) error {
		if token.Issuer != issuer {
			return fmt.Errorf(`token was not issued by "%s"`, issuer)
		}
		return nil
	}
}

// Subject validates that the JSONToken subject has the specified value.
func Subject(subject string) Validator {
	return func(token *JSONToken) error {
		if token.Subject != subject {
			return fmt.Errorf(`token was not related to subject "%s"`, subject)
		}
		return nil
	}
}

// ValidAt validates whether the token is valid at the specified time, based on
// the values of the  IssuedAt, NotBefore and Expiration claims in the token.
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
