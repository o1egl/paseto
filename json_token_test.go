package paseto

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJsonToken(t *testing.T) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	const (
		audience = "test audience"
		issuer   = "test issuer"
		jti      = "test jti"
		subject  = "test subject"
	)

	type CustomStruct struct {
		Foo string
		Bar int
	}

	var (
		iss = time.Now().Add(-2 * time.Hour)
		exp = iss.Add(24 * time.Hour)
		nbt = iss.Add(10 * time.Minute)

		customClaims = map[string]interface{}{
			"string":         "test value",
			"int":            123,
			"int8":           int8(8),
			"int16":          int16(16),
			"int32":          int32(32),
			"int64":          int64(64),
			"uint8":          uint8(8),
			"uint16":         uint16(16),
			"uint32":         uint32(32),
			"uint64":         uint64(64),
			"bool":           true,
			"float32":        float32(32.55),
			"float64":        float64(64.55),
			"byte":           byte(1),
			"byte_arr":       []byte{1, 2, 3},
			"byte_arr_nil":   []byte(nil),
			"string_arr":     []string{"foo", "bar"},
			"string_arr_nil": []string(nil),
			"struct": CustomStruct{
				Foo: "Baz",
				Bar: 321,
			},
			"ptr": &CustomStruct{
				Foo: "ptr Baz",
				Bar: 456,
			},
		}
	)

	jsonToken := JSONToken{
		Audience:   audience,
		Issuer:     issuer,
		Jti:        jti,
		Subject:    subject,
		IssuedAt:   iss,
		Expiration: exp,
		NotBefore:  nbt,
	}

	for key, value := range customClaims {
		jsonToken.Set(key, value)
	}

	v2 := NewV2()

	if token, err := v2.Encrypt(symmetricKey, jsonToken, nil); assert.NoError(t, err) {
		var obtainedToken JSONToken
		if err := v2.Decrypt(token, symmetricKey, &obtainedToken, nil); assert.NoError(t, err) {
			assert.NoError(t, obtainedToken.Validate())
			assert.Equal(t, audience, obtainedToken.Audience)
			assert.Equal(t, issuer, obtainedToken.Issuer)
			assert.Equal(t, jti, obtainedToken.Jti)
			assert.Equal(t, subject, obtainedToken.Subject)
			assert.Equal(t, exp.Unix(), obtainedToken.Expiration.Unix())
			assert.Equal(t, iss.Unix(), obtainedToken.IssuedAt.Unix())
			assert.Equal(t, nbt.Unix(), obtainedToken.NotBefore.Unix())

			for key, value := range customClaims {
				t.Run("claim "+key, func(t *testing.T) {
					newValue := reflect.New(reflect.TypeOf(value))
					if assert.NoError(t, obtainedToken.Get(key, newValue.Interface())) {
						assert.Equal(t, value, newValue.Elem().Interface())
					}
				})
			}
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
			err: "failed to parse expiration claim",
		},
		"Invalid IssuedAt time format": {
			srt: `{"iat":"11/03/2018"}`,
			err: "failed to parse issued at claim",
		},
		"Invalid NotBefore time format": {
			srt: `{"nbf":"11/03/2018"}`,
			err: "failed to parse not before claim",
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
