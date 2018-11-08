package paseto

import (
	"crypto"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testEncryptDecrypt(t *testing.T, impl Protocol) {
	t.Helper()
	type Case struct {
		payload         interface{}
		footer          interface{}
		obtainedPayload interface{}
		obtainedFooter  interface{}
	}

	key, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")

	cases := map[string]Case{
		"struct payload, struct footer": {
			payload:         &TestPerson{Name: "John", Age: 30},
			footer:          &TestPerson{Name: "Antony", Age: 60},
			obtainedPayload: &TestPerson{},
			obtainedFooter:  &TestPerson{},
		},
		"string payload, string footer": {
			payload:         sPtr("payload"),
			footer:          sPtr("footer"),
			obtainedPayload: sPtr(""),
			obtainedFooter:  sPtr(""),
		},
		"[]byte payload, []byte footer": {
			payload:         baPtr([]byte("payload")),
			footer:          baPtr([]byte("footer")),
			obtainedPayload: baPtr([]byte("")),
			obtainedFooter:  baPtr([]byte("")),
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if token, err := impl.Encrypt(key, test.payload, test.footer); assert.NoError(t, err) {
				if err := impl.Decrypt(token, key, test.obtainedPayload, test.obtainedFooter); assert.NoError(t, err) {
					assert.Equal(t, test.payload, test.obtainedPayload)
					assert.EqualValues(t, test.footer, test.obtainedFooter)
				}
			}
		})
	}

	t.Run("non pointer string payload and footer", func(t *testing.T) {
		payload := "payload"
		footer := "footer"
		if token, err := impl.Encrypt(key, payload, footer); assert.NoError(t, err) {
			var obtainedPayload string
			var obtainedFooter string
			if err := impl.Decrypt(token, key, &obtainedPayload, &obtainedFooter); assert.NoError(t, err) {
				assert.Equal(t, payload, obtainedPayload)
				assert.EqualValues(t, footer, obtainedFooter)
			}
		}
	})
}

func testSign(t *testing.T, impl Protocol, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	t.Helper()

	cases := map[string]struct {
		payload interface{}
		footer  interface{}
	}{
		"Non empty payload, empty footer": {
			payload: []byte("Lorem Ipsum"),
		},
		"Non empty payload, non empty footer": {
			payload: []byte("Lorem Ipsum"),
			footer:  []byte("footer"),
		},
		"Struct payload, struct footer": {
			payload: TestPerson{Name: "John", Age: 30},
			footer:  TestPerson{Name: "Antony", Age: 60},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if token, err := impl.Sign(privateKey, test.payload, test.footer); assert.NoError(t, err) {
				var obtainedPayload = ptrOf(test.payload)
				var obtainedFooter = ptrOf(test.footer)
				if assert.NoError(t, impl.Verify(token, publicKey, obtainedPayload, obtainedFooter)) {
					assert.Equal(t, test.payload, valOf(obtainedPayload), "Payload does not match")
					assert.Equal(t, test.footer, valOf(obtainedFooter), "Footer does not match")
				}
			}
		})
	}
}

func ptrOf(i interface{}) interface{} {
	if i == nil {
		return nil
	}
	val := reflect.ValueOf(i)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	val = reflect.New(val.Type())

	return val.Interface()
}

func valOf(i interface{}) interface{} {
	if i == nil {
		return nil
	}
	val := reflect.ValueOf(i)
	switch val.Kind() {
	case reflect.Ptr:
		return val.Elem().Interface()
	default:
		panic("Interface is not a pointer")
	}
}

func sPtr(v string) *string {
	return &v
}

func baPtr(v []byte) *[]byte {
	return &v
}
