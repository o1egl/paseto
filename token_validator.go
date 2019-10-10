package paseto

import (
	"fmt"
	"time"
)

// Validator defines a JSONToken validator function.
type Validator func(token *JSONToken) error

// ForAudience validates that the JSONToken audience has the specified value.
func ForAudience(audience string) Validator {
	return func(token *JSONToken) error {
		if token.Audience != audience {
			return fmt.Errorf(`token was not intended for "%s" audience: %w`, audience, ErrTokenValidationError)
		}
		return nil
	}
}

// IdentifiedBy validates that the JSONToken JTI has the specified value.
func IdentifiedBy(jti string) Validator {
	return func(token *JSONToken) error {
		if token.Jti != jti {
			return fmt.Errorf(`token was expected to be identified by "%s": %w`, jti, ErrTokenValidationError)
		}
		return nil
	}
}

// IssuedBy validates that the JSONToken issuer has the specified value.
func IssuedBy(issuer string) Validator {
	return func(token *JSONToken) error {
		if token.Issuer != issuer {
			return fmt.Errorf(`token was not issued by "%s": %w`, issuer, ErrTokenValidationError)
		}
		return nil
	}
}

// Subject validates that the JSONToken subject has the specified value.
func Subject(subject string) Validator {
	return func(token *JSONToken) error {
		if token.Subject != subject {
			return fmt.Errorf(`token was not related to subject "%s": %w`, subject, ErrTokenValidationError)
		}
		return nil
	}
}

// ValidAt validates whether the token is valid at the specified time, based on
// the values of the  IssuedAt, NotBefore and Expiration claims in the token.
func ValidAt(t time.Time) Validator {
	return func(token *JSONToken) error {
		if !token.IssuedAt.IsZero() && t.Before(token.IssuedAt) {
			return fmt.Errorf("token was issued in the future: %w", ErrTokenValidationError)
		}
		if !token.NotBefore.IsZero() && t.Before(token.NotBefore) {
			return fmt.Errorf("token cannot be used yet: %w", ErrTokenValidationError)
		}
		if !token.Expiration.IsZero() && t.After(token.Expiration) {
			return fmt.Errorf("token has expired: %w", ErrTokenValidationError)
		}
		return nil
	}
}
