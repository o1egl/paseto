package paseto

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestJsonToken_Validate(t *testing.T) {
	now := time.Now()
	exp := now.Add(24 * time.Hour)
	nbt := now

	jsonToken := JSONToken{
		Audience:   "test",
		Issuer:     "test_service",
		Jti:        "123",
		Subject:    "test_subject",
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}

	jsonToken.Validate(ForAudience("test"), IdentifiedBy("123"), IssuedBy("test_service"),
		Subject("test_subject"), ValidAt(now.Add(2*time.Hour)))
}

func TestJsonToken_Validate_Err(t *testing.T) {
	cases := []struct {
		token     JSONToken
		validator Validator
		err       string
	}{
		{
			token: JSONToken{
				Audience: "abcd",
			},
			validator: ForAudience("test"),
			err:       "token was not intended for",
		},
		{
			token: JSONToken{
				Jti: "abcd",
			},
			validator: IdentifiedBy("test"),
			err:       "token was expected to be identified by",
		},
		{
			token: JSONToken{
				Issuer: "abcd",
			},
			validator: IssuedBy("test"),
			err:       "token was not issued by",
		},
		{
			token: JSONToken{
				Subject: "abcd",
			},
			validator: Subject("test"),
			err:       "token was not related to subject",
		},
		{
			token: JSONToken{
				IssuedAt: time.Now().Add(2 * time.Hour),
			},
			validator: ValidAt(time.Now()),
			err:       "token was issued in the future",
		},
		{
			token: JSONToken{
				NotBefore: time.Now().Add(2 * time.Hour),
			},
			validator: ValidAt(time.Now()),
			err:       "token cannot be used yet",
		},
		{
			token: JSONToken{
				Expiration: time.Now().Add(-2 * time.Hour),
			},
			validator: ValidAt(time.Now()),
			err:       "token has expired",
		},
	}

	for _, c := range cases {
		if err := c.token.Validate(c.validator); assert.Error(t, err) {
			assert.Contains(t, err.Error(), c.err)
		}
	}
}
