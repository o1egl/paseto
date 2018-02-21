package paseto

import (
	"encoding/hex"
	"testing"

	"crypto"

	"github.com/stretchr/testify/assert"
)

func _testEncryptDecrypt(t *testing.T, impl Protocol) {
	type Case struct {
		payload         interface{}
		footer          interface{}
		obtainedPayload interface{}
		obtainedFooter  interface{}
	}

	key, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")

	cases := []Case{
		{
			payload:         &TestPerson{Name: "John", Age: 30},
			footer:          &TestPerson{Name: "Antony", Age: 60},
			obtainedPayload: &TestPerson{},
			obtainedFooter:  &TestPerson{},
		},
		{
			payload:         sPtr("payload"),
			footer:          sPtr("footer"),
			obtainedPayload: sPtr(""),
			obtainedFooter:  sPtr(""),
		},
		{
			payload:         baPtr([]byte("payload")),
			footer:          baPtr([]byte("footer")),
			obtainedPayload: baPtr([]byte("")),
			obtainedFooter:  baPtr([]byte("")),
		},
	}

	for _, c := range cases {
		if token, err := impl.Encrypt(key, c.payload, WithFooter(c.footer)); assert.NoError(t, err) {
			if err := impl.Decrypt(token, key, c.obtainedPayload, c.obtainedFooter); assert.NoError(t, err) {
				assert.Equal(t, c.payload, c.obtainedPayload)
				assert.EqualValues(t, c.footer, c.obtainedFooter)
			}
		}
	}

	payload := "payload"
	footer := "footer"
	if token, err := impl.Encrypt(key, payload, WithFooter(footer)); assert.NoError(t, err) {
		var obtainedPayload string
		var obtainedFooter string
		if err := impl.Decrypt(token, key, &obtainedPayload, &obtainedFooter); assert.NoError(t, err) {
			assert.Equal(t, payload, obtainedPayload)
			assert.EqualValues(t, footer, obtainedFooter)
		}
	}
}

func _testSign(t *testing.T, impl Protocol, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	{
		payload := []byte("Lorem Ipsum")
		if token, err := impl.Sign(privateKey, payload); assert.NoError(t, err) {
			var obtainedPayload []byte
			if assert.NoError(t, impl.Verify(token, publicKey, &obtainedPayload, nil)) {
				assert.Equal(t, payload, obtainedPayload)
			}
		}
	}

	{
		payload := []byte("Lorem Ipsum")
		footer := []byte("footer")
		if token, err := impl.Sign(privateKey, payload, WithFooter(footer)); assert.NoError(t, err) {
			var obtainedPayload []byte
			var obtainedFooter []byte
			if assert.NoError(t, impl.Verify(token, publicKey, &obtainedPayload, &obtainedFooter)) {
				assert.Equal(t, payload, obtainedPayload)
				assert.Equal(t, footer, obtainedFooter)
			}
		}
	}

	{
		payload := TestPerson{Name: "John", Age: 30}
		footer := TestPerson{Name: "Antony", Age: 60}
		if token, err := impl.Sign(privateKey, &payload, WithFooter(&footer)); assert.NoError(t, err) {
			var obtainedPayload TestPerson
			var obtainedFooter TestPerson
			if assert.NoError(t, impl.Verify(token, publicKey, &obtainedPayload, &obtainedFooter)) {
				assert.Equal(t, payload, obtainedPayload)
				assert.Equal(t, footer, obtainedFooter)
			}
		}
	}
}

func sPtr(v string) *string {
	return &v
}

func baPtr(v []byte) *[]byte {
	return &v
}
