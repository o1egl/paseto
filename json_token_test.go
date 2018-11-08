package paseto

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJsonToken(t *testing.T) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")

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

	jsonToken.Set("data", "this is a signed message")

	v2 := NewV2()

	if token, err := v2.Encrypt(symmetricKey, jsonToken, nil); assert.NoError(t, err) {
		var obtainedToken JSONToken
		if err := v2.Decrypt(token, symmetricKey, &obtainedToken, nil); assert.NoError(t, err) {
			assert.NoError(t, obtainedToken.Validate())
			assert.Equal(t, jsonToken.Audience, obtainedToken.Audience)
			assert.Equal(t, jsonToken.Issuer, obtainedToken.Issuer)
			assert.Equal(t, jsonToken.Jti, obtainedToken.Jti)
			assert.Equal(t, jsonToken.Subject, obtainedToken.Subject)
			assert.Equal(t, jsonToken.Expiration.Unix(), obtainedToken.Expiration.Unix())
			assert.Equal(t, jsonToken.IssuedAt.Unix(), obtainedToken.IssuedAt.Unix())
			assert.Equal(t, jsonToken.NotBefore.Unix(), obtainedToken.NotBefore.Unix())
			assert.Equal(t, jsonToken.Get("data"), obtainedToken.Get("data"))
		}
	}
}

func TestJsonToken_MarshalJSON(t *testing.T) {
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

	if b, err := json.Marshal(jsonToken); assert.NoError(t, err) {
		var obtainedToken JSONToken
		if err := json.Unmarshal(b, &obtainedToken); assert.NoError(t, err) {
			assert.Equal(t, jsonToken.Audience, obtainedToken.Audience)
			assert.Equal(t, jsonToken.Issuer, obtainedToken.Issuer)
			assert.Equal(t, jsonToken.Jti, obtainedToken.Jti)
			assert.Equal(t, jsonToken.Subject, obtainedToken.Subject)
			assert.Equal(t, jsonToken.Expiration.Unix(), obtainedToken.Expiration.Unix())
			assert.Equal(t, jsonToken.IssuedAt.Unix(), obtainedToken.IssuedAt.Unix())
			assert.Equal(t, jsonToken.NotBefore.Unix(), obtainedToken.NotBefore.Unix())
		}
	}
}

func TestJsonToken_UnmarshalJSON_Err(t *testing.T) {
	cases := map[string]struct {
		srt string
		err string
	}{
		"Invalid json": {
			srt: `"test"`,
			err: "cannot unmarshal",
		},
		"Invalid Expiration time format": {
			srt: `{"exp":"11/03/2018"}`,
			err: "incorrect time format for Expiration field",
		},
		"Invalid IssuedAt time format": {
			srt: `{"iat":"11/03/2018"}`,
			err: "incorrect time format for IssuedAt field",
		},
		"Invalid NotBefore time format": {
			srt: `{"nbf":"11/03/2018"}`,
			err: "incorrect time format for NotBefore field",
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(test.srt), &JSONToken{}); assert.Error(t, err) {
				assert.Contains(t, err.Error(), test.err)
			}
		})
	}
}
