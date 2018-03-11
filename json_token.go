package paseto

import (
	"encoding/json"
	"fmt"
	"time"
)

// JSONToken defines predefined token payload struct
type JSONToken struct {
	Audience   string
	Issuer     string
	Jti        string
	Subject    string
	Expiration time.Time
	IssuedAt   time.Time
	NotBefore  time.Time
	claims     map[string]string
}

// Get return custom claim
func (t *JSONToken) Get(key string) string {
	return t.claims[key]
}

// Set sets custom claim
func (t *JSONToken) Set(key string, value string) {
	if t.claims == nil {
		t.claims = make(map[string]string)
	}
	t.claims[key] = value
}

// MarshalJSON implements json.Marshaler interface
func (t JSONToken) MarshalJSON() ([]byte, error) {
	if t.claims == nil {
		t.claims = make(map[string]string)
	}
	if t.Audience != "" {
		t.claims["aud"] = t.Audience
	}
	if t.Issuer != "" {
		t.claims["iss"] = t.Issuer
	}
	if t.Jti != "" {
		t.claims["jti"] = t.Jti
	}
	if t.Subject != "" {
		t.claims["sub"] = t.Subject
	}
	if !t.Expiration.IsZero() {
		t.claims["exp"] = t.Expiration.Format(time.RFC3339)
	}
	if !t.IssuedAt.IsZero() {
		t.claims["iat"] = t.IssuedAt.Format(time.RFC3339)
	}
	if !t.NotBefore.IsZero() {
		t.claims["nbf"] = t.NotBefore.Format(time.RFC3339)
	}

	return json.Marshal(t.claims)
}

// UnmarshalJSON implements json.Unmarshaler interface
func (t *JSONToken) UnmarshalJSON(data []byte) error {
	var err error
	if err := json.Unmarshal(data, &t.claims); err != nil {
		return err
	}

	t.Audience = t.claims["aud"]
	t.Issuer = t.claims["iss"]
	t.Jti = t.claims["jti"]
	t.Subject = t.claims["sub"]

	if timeStr, ok := t.claims["exp"]; ok {
		t.Expiration, err = time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return fmt.Errorf(`incorrect time format for Expiration field "%s". It should be RFC3339`, timeStr)
		}
	}

	if timeStr, ok := t.claims["iat"]; ok {
		t.IssuedAt, err = time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return fmt.Errorf(`incorrect time format for IssuedAt field "%s". It should be RFC3339`, timeStr)
		}
	}

	if timeStr, ok := t.claims["nbf"]; ok {
		t.NotBefore, err = time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return fmt.Errorf(`incorrect time format for NotBefore field "%s". It should be RFC3339`, timeStr)
		}
	}

	return nil
}

// Validate validates token with given validators.
// If no validators specified, then by default it validates token with ValidAt(time.Now())
// which checks IssuedAt, NotBefore and Expiration fields with current time.
func (t *JSONToken) Validate(validators ...Validator) error {
	var err error
	if len(validators) == 0 {
		validators = append(validators, ValidAt(time.Now()))
	}
	for _, validator := range validators {
		if err = validator(t); err != nil {
			return err
		}
	}
	return nil
}
