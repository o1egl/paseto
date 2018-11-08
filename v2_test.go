package paseto

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestPasetoV2_Encrypt_Compatibility(t *testing.T) {
	nullKey := bytes.Repeat([]byte{0}, 32)
	fullKey := bytes.Repeat([]byte{0xff}, 32)
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	nonce := bytes.Repeat([]byte{0}, 24)
	nonce2, _ := hex.DecodeString("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
	footer := []byte("Cuon Alpinus")
	payload := []byte("Love is stronger than hate or fear")
	v2 := NewV2()

	cases := map[string]struct {
		key     []byte
		token   string
		nonce   []byte
		payload []byte
		footer  []byte
	}{
		"Empty message, empty footer, empty nonce, null key": {
			key:   nullKey,
			token: "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
			nonce: nonce,
		},
		"Empty message, empty footer, empty nonce, full key": {
			key:   fullKey,
			token: "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg",
			nonce: nonce,
		},
		"Empty message, empty footer, empty nonce, symmetric key": {
			key:   symmetricKey,
			token: "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA",
			nonce: nonce,
		},
		"Empty message, non-empty footer, empty nonce, null key": {
			key:    nullKey,
			token:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz",
			nonce:  nonce,
			footer: footer,
		},
		"Empty message, non-empty footer, empty nonce, full key": {
			key:    fullKey,
			token:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz",
			nonce:  nonce,
			footer: footer,
		},
		"Empty message, non-empty footer, empty nonce, symmetric key": {
			key:    symmetricKey,
			token:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz",
			nonce:  nonce,
			footer: footer,
		},
		"Non-empty message, empty footer, empty nonce, null key": {
			key:     nullKey,
			token:   "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0",
			nonce:   nonce,
			payload: payload,
		},
		"Non-empty message, empty footer, empty nonce, full key": {
			key:     fullKey,
			token:   "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw",
			nonce:   nonce,
			payload: payload,
		},
		"Non-empty message, empty footer, empty nonce, symmetric key": {
			key:     symmetricKey,
			token:   "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U",
			nonce:   nonce,
			payload: payload,
		},
		"Non-empty message, non-empty footer, non-empty nonce, null key": {
			key:     nullKey,
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz",
			nonce:   nonce2,
			payload: payload,
			footer:  footer,
		},
		"Non-empty message, non-empty footer, non-empty nonce, full key": {
			key:     fullKey,
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz",
			nonce:   nonce2,
			payload: payload,
			footer:  footer,
		},
		"Non-empty message, non-empty footer, non-empty nonce, symmetric key": {
			key:     symmetricKey,
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
			nonce:   nonce2,
			payload: payload,
			footer:  footer,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			v2.nonce = test.nonce
			if token, err := v2.Encrypt(test.key, test.payload, test.footer); assert.NoError(t, err) {
				assert.Equal(t, test.token, token)
			}
		})
	}
}

func TestPasetoV2_Sign_Compatibility(t *testing.T) {
	b, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	privateKey := ed25519.PrivateKey(b)
	v2 := NewV2()

	cases := map[string]struct {
		token   string
		payload string
		footer  string
	}{
		"Empty string, 32-character NUL byte key": {
			token: "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA",
		},
		"Empty string, 32-character NUL byte key, non-empty footer": {
			token:  "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz",
			footer: "Cuon Alpinus",
		},
		"Non-empty string, 32-character 0xFF byte key": {
			token:   "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM",
			payload: "Frank Denis rocks",
		},

		"Non-empty string, 32-character 0xFF byte key. (One character difference)": {
			token:   "v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML",
			payload: "Frank Denis rockz",
		},
		"Non-empty string, 32-character 0xFF byte key, non-empty footer": {
			token:   "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
			payload: "Frank Denis rocks",
			footer:  "Cuon Alpinus",
		},
		"Json payload": {
			token:   "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI",
			payload: `{"data":"this is a signed message","expires":"2019-01-01T00:00:00+00:00"}`,
		},
		"Json payload with footer": {
			token:   "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
			payload: `{"data":"this is a signed message","expires":"2019-01-01T00:00:00+00:00"}`,
			footer:  "Paragon Initiative Enterprises",
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if genToken, err := v2.Sign(privateKey, test.payload, test.footer); assert.NoError(t, err) {
				assert.Equal(t, test.token, genToken)
			}
		})
	}
}

func TestPasetoV2_EncryptDecrypt(t *testing.T) {
	testEncryptDecrypt(t, NewV2())
}

func TestPasetoV2_SignVerify(t *testing.T) {
	b, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	privateKey := ed25519.PrivateKey(b)

	b, _ = hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	publicKey := ed25519.PublicKey(b)

	testSign(t, NewV2(), privateKey, publicKey)
}

func TestPasetoV2_Verify_Error(t *testing.T) {
	b, _ := hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	publicKey := ed25519.PublicKey(b)
	v2 := NewV2()

	cases := map[string]struct {
		token     string
		publicKey crypto.PublicKey
		payload   interface{}
		footer    interface{}
		error     error
	}{
		"Payload unmarshal error": {
			token:     "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
			publicKey: publicKey,
			payload:   &TestPerson{},
			footer:    nil,
			error:     ErrDataUnmarshal,
		},
		"Footer unmarshal error": {
			token:     "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
			publicKey: publicKey,
			payload:   nil,
			footer:    &TestPerson{},
			error:     ErrDataUnmarshal,
		},
		"Incorrect token format: invalid sign size": {
			token:     "v2.public.eyJOYW1lIjoiSm9obiIsIkF",
			publicKey: publicKey,
			payload:   sPtr(""),
			footer:    sPtr(""),
			error:     ErrIncorrectTokenFormat,
		},
		"Incorrect token format: too many parts": {
			token:     "v2.public.eyJOYW1lIj.oiSm9o.biIsIkF",
			publicKey: publicKey,
			payload:   sPtr(""),
			footer:    sPtr(""),
			error:     ErrIncorrectTokenFormat,
		},
		"ErrIncorrectPublicKeyType": {
			token:     "v2.public.eyJOYW1lIj.oiSm9o.biIsIkF",
			publicKey: "hello",
			payload:   nil,
			footer:    nil,
			error:     ErrIncorrectPublicKeyType,
		},
		"ErrInvalidSignature": {
			token:     "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F",
			publicKey: publicKey,
			payload:   nil,
			footer:    nil,
			error:     ErrInvalidSignature,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := v2.Verify(test.token, test.publicKey, test.payload, test.footer)
			assert.Equal(t, test.error, errors.Cause(err))
		})
	}
}

func TestPasetoV2_Decrypt_Error(t *testing.T) {
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	v2 := NewV2()

	cases := map[string]struct {
		token   string
		payload interface{}
		footer  interface{}
		error   error
	}{
		"Payload unmarshal error": {
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
			payload: struct{}{},
			footer:  baPtr([]byte{}),
			error:   ErrDataUnmarshal,
		},
		"Footer unmarshal error": {
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  struct{}{},
			error:   ErrDataUnmarshal,
		},
		"Invalid token header": {
			token:   "v2.test.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwy.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrIncorrectTokenHeader,
		},
		"Too many parts": {
			token:   "v2.local.rElw-WywOu.SD1Mwy.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrIncorrectTokenFormat,
		},
		"Incorrect nonce size": {
			token:   "v2.local.vadkjCfBwRua_Sj-RVw.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrIncorrectTokenFormat,
		},
		"Invalid token auth": {
			token:   "v2.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTn.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrInvalidTokenAuth,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := v2.Decrypt(test.token, symmetricKey, test.payload, test.footer)
			assert.Equal(t, test.error, errors.Cause(err))
		})
	}
}

func TestPasetoV2_Sign_Error(t *testing.T) {
	v2 := NewV2()

	cases := map[string]struct {
		key     crypto.PrivateKey
		payload interface{}
		footer  interface{}
		err     error
	}{
		"Invalid key": {
			key: "incorrect",
			err: ErrIncorrectPrivateKeyType,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v2.Sign(test.key, test.payload, test.footer)
			assert.EqualError(t, err, test.err.Error())
		})
	}
}
