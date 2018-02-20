package paseto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestPasetoV2_Encrypt_Compatibility(t *testing.T) {
	var emptyPayload []byte
	nullKey := bytes.Repeat([]byte{0}, 32)
	fullKey := bytes.Repeat([]byte{0xff}, 32)
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	nonce := bytes.Repeat([]byte{0}, 24)
	nonce2, _ := hex.DecodeString("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
	footer := []byte("Cuon Alpinus")
	payload := []byte("Love is stronger than hate or fear")

	v2 := NewV2()

	// Empty message, empty footer, empty nonce
	if token, err := v2.Encrypt(nullKey, emptyPayload, withNonce(nonce)); assert.NoError(t, err) {
		expected := "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(fullKey, emptyPayload, withNonce(nonce)); assert.NoError(t, err) {
		expected := "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(symmetricKey, emptyPayload, withNonce(nonce)); assert.NoError(t, err) {
		expected := "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA"
		assert.Equal(t, expected, token)
	}

	// Empty message, non-empty footer, empty nonce
	if token, err := v2.Encrypt(nullKey, emptyPayload, withNonce(nonce), WithFooter(footer)); assert.NoError(t, err) {
		expected := "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(fullKey, emptyPayload, withNonce(nonce), WithFooter(footer)); assert.NoError(t, err) {
		expected := "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(symmetricKey, emptyPayload, withNonce(nonce), WithFooter(footer)); assert.NoError(t, err) {
		expected := "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz"
		assert.Equal(t, expected, token)
	}

	// Non-empty message, empty footer, empty nonce
	if token, err := v2.Encrypt(nullKey, payload, withNonce(nonce)); assert.NoError(t, err) {
		expected := "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(fullKey, payload, withNonce(nonce)); assert.NoError(t, err) {
		expected := "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(symmetricKey, payload, withNonce(nonce)); assert.NoError(t, err) {
		expected := "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U"
		assert.Equal(t, expected, token)
	}

	// Non-empty message, non-empty footer, non-empty nonce
	if token, err := v2.Encrypt(nullKey, payload, withNonce(nonce2), WithFooter(footer)); assert.NoError(t, err) {
		expected := "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(fullKey, payload, withNonce(nonce2), WithFooter(footer)); assert.NoError(t, err) {
		expected := "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz"
		assert.Equal(t, expected, token)
	}

	if token, err := v2.Encrypt(symmetricKey, payload, withNonce(nonce2), WithFooter(footer)); assert.NoError(t, err) {
		expected := "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz"
		assert.Equal(t, expected, token)
	}
}

func TestPasetoV2_Sign_Compatibility(t *testing.T) {
	b, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	privateKey := ed25519.PrivateKey(b)
	v2 := NewV2()

	cases := map[string]struct {
		payload string
		footer  string
	}{
		// Empty string, 32-character NUL byte key.
		"v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA": {},
		// Empty string, 32-character NUL byte key, non-empty footer.
		"v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz": {
			footer: "Cuon Alpinus",
		},
		// Non-empty string, 32-character 0xFF byte key.
		"v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM": {
			payload: "Frank Denis rocks",
		},
		// Non-empty string, 32-character 0xFF byte key. (One character difference)
		"v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML": {
			payload: "Frank Denis rockz",
		},
		// Non-empty string, 32-character 0xFF byte key, non-empty footer.
		"v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz": {
			payload: "Frank Denis rocks",
			footer:  "Cuon Alpinus",
		},
		"v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI": {
			payload: `{"data":"this is a signed message","expires":"2019-01-01T00:00:00+00:00"}`,
		},
		"v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz": {
			payload: `{"data":"this is a signed message","expires":"2019-01-01T00:00:00+00:00"}`,
			footer:  "Paragon Initiative Enterprises",
		},
	}

	for token, c := range cases {
		if genToken, err := v2.Sign(privateKey, c.payload, WithFooter(c.footer)); assert.NoError(t, err) {
			assert.Equal(t, token, genToken)
		}
	}
}
