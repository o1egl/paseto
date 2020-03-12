package paseto

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"

	errors "golang.org/x/xerrors"
)

var (
	// ErrTypeCast type cast error
	ErrTypeCast = errors.New("type cast error")
	// ErrClaimNotFound claim not found error
	ErrClaimNotFound = errors.New("claim not found")
)

// JSONToken defines standard token payload claims and allows for additional
// claims to be added. All of the standard claims are optional.
type JSONToken struct {
	// Audience identifies the intended recipients of the token.
	// It should be a string or a URI and is case sensitive.
	Audience string
	// Issuer identifies the entity which issued the token.
	// It should be a string or a URI and is case sensitive.
	Issuer string
	// JTI is a globally unique identifier for the token. It must be created in
	// such a way as to ensure that there is negligible probability that the same
	// value will be used in another token.
	Jti string
	// Subject identifies the principal entity that is the subject of the token.
	// For example, for an authentication token, the subject might be the user ID
	// of a person.
	Subject string
	// Expiration is a time on or after which the token must not be accepted for processing.
	Expiration time.Time
	// IssuedAt is the time at which the token was issued.
	IssuedAt time.Time
	// NotBefore is a time on or before which the token must not be accepted for
	// processing.
	NotBefore time.Time
	claims    map[string]interface{}
}

// MapUnmarshaler is the interface used in mapstructure decoder hook.
type MapUnmarshaler interface {
	// UnmarshalMap receives `v` from DecodeHookFunc.
	// Returned value is used by mapstructure for further processing.
	UnmarshalMap(interface{}) (interface{}, error)
}

func decodeHook(from, to reflect.Type, v interface{}) (interface{}, error) {
	unmarshalerType := reflect.TypeOf((*MapUnmarshaler)(nil)).Elem()
	if to.Implements(unmarshalerType) {
		// invoke UnmarshalMap by name
		if method, ok := to.MethodByName("UnmarshalMap"); ok {
			in := []reflect.Value{reflect.New(to).Elem(), reflect.ValueOf(v)}
			r := method.Func.Call(in)
			if !r[1].IsNil() {
				return nil, r[1].Interface().(error)
			}
			// get first return parameter and cast reflect.Value
			v = r[0].Interface().(interface{})
		}
	}
	return v, nil
}

// Get the value of the claim and uses reflection to store it in the value pointed to by v.
// If the claim doesn't exist an ErrClaimNotFound error is returned
func (t *JSONToken) Get(key string, v interface{}) error {
	val, ok := t.claims[key]
	if !ok {
		return ErrClaimNotFound
	}
	switch f := v.(type) {
	case *string:
		s, ok := val.(string)
		if !ok {
			return errors.Errorf(`failed to cast value to string: %w`, ErrTypeCast)
		}
		*f = s
	case *time.Time:
		s, ok := val.(string)
		if !ok {
			return errors.Errorf(`failed to cast value to time.Time: %w`, ErrTypeCast)
		}
		date, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return errors.Errorf(`failed to parse time value: %v: %w`, err, ErrTypeCast)
		}
		*f = date
	case *[]byte:
		if val == nil {
			return nil
		}
		s, ok := val.(string)
		if !ok {
			return errors.Errorf(`failed to cast value to []byte: %w`, ErrTypeCast)
		}
		bytes, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return errors.Errorf(`failed to decode []byte: %w`, ErrTypeCast)
		}
		*f = bytes
	default:
		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: decodeHook,
			Result:     v,
		})
		if err != nil {
			return errors.Errorf("failed to create map decoder: %w", err)
		}
		if err := decoder.Decode(val); err != nil {
			return errors.Errorf(`failed to cast value to %s: %v: %w`, reflect.TypeOf(v).String(), err, ErrTypeCast)
		}
	}
	return nil
}

// Set sets the value of a custom claim
func (t *JSONToken) Set(key string, value interface{}) {
	if t.claims == nil {
		t.claims = make(map[string]interface{})
	}
	t.claims[key] = value
}

// MarshalJSON implements json.Marshaler interface
// nolint:gocritic
func (t JSONToken) MarshalJSON() ([]byte, error) {
	if t.claims == nil {
		t.claims = make(map[string]interface{})
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
//nolint:gocyclo
func (t *JSONToken) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &t.claims); err != nil {
		return err
	}

	if err := t.Get("aud", &t.Audience); err != nil && !errors.Is(err, ErrClaimNotFound) {
		return errors.Errorf("failed to parse audience claim: %w", err)
	}
	if err := t.Get("iss", &t.Issuer); err != nil && !errors.Is(err, ErrClaimNotFound) {
		return errors.Errorf("failed to parse issuer claim: %w", err)
	}
	if err := t.Get("jti", &t.Jti); err != nil && !errors.Is(err, ErrClaimNotFound) {
		return errors.Errorf("failed to parse jti claim: %w", err)
	}
	if err := t.Get("sub", &t.Subject); err != nil && !errors.Is(err, ErrClaimNotFound) {
		return errors.Errorf("failed to parse subject claim: %w", err)
	}
	if err := t.Get("exp", &t.Expiration); err != nil && !errors.Is(err, ErrClaimNotFound) {
		return errors.Errorf("failed to parse expiration claim: %w", err)
	}
	if err := t.Get("iat", &t.IssuedAt); err != nil && !errors.Is(err, ErrClaimNotFound) {
		return errors.Errorf("failed to parse issued at claim: %w", err)
	}
	if err := t.Get("nbf", &t.NotBefore); err != nil && !errors.Is(err, ErrClaimNotFound) {
		return errors.Errorf("failed to parse not before claim: %w", err)
	}

	return nil
}

// Validate validates a token with the given validators. If no validators are
// specified, then by default it validates the token with ValidAt(time.Now()),
// which checks IssuedAt, NotBefore and Expiration fields against the current
// time.
func (t *JSONToken) Validate(validators ...Validator) error {
	if len(validators) == 0 {
		validators = append(validators, ValidAt(time.Now()))
	}
	for _, validator := range validators {
		if err := validator(t); err != nil {
			return err
		}
	}
	return nil
}
