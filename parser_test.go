package paseto

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestParse(t *testing.T) {
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")

	cases := map[string]struct {
		token   string
		version Version
		payload interface{}
		footer  interface{}
	}{
		"v1.local": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
			version: Version1,
			payload: []byte("Love is stronger than hate or fear"),
			footer:  []byte("Cuon Alpinus"),
		},
		"v1.public": {
			token:   "v1.public.TG9yZW0gSXBzdW1684wbBiSvpwhED_5bdFnF2ithKoKDyzEyTOLUlFnz83IibTKCOw3LPOEp8xKM67EYOw1xU6OBBOdLQT-XO5mKMg51JJ4J91IBDwDazDex0D2UQphr7i8gPGP_5FyjlNincP_rToVbYOOzfk9cmnH1-iLmOxxbrsa7-v08Gx12ib-Z-KxKBXBHbxI8uvauVWUVS6A7rl0eAlb6SecSPPQpxQnD1zakA-nGFUbWq5Zx8XqgVZ-VidcGcd7kmhZ-bMy4Z1uGOWmAXHC793v8sbXuRdroZM8kmO0pqQMoE_wmlriIxflFABCa1PPWi5YB87aVF3oIWHYXawZXxRwxevgK.Zm9vdGVy",
			version: Version1,
			payload: []byte("Lorem Ipsum"),
			footer:  []byte("footer"),
		},
		"v2.local": {
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
			version: Version2,
			payload: []byte("Love is stronger than hate or fear"),
			footer:  []byte("Cuon Alpinus"),
		},
		"v2.public": {
			token:   "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
			version: Version2,
			payload: []byte("Frank Denis rocks"),
			footer:  []byte("Cuon Alpinus"),
		},
	}

	b, _ := hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	v2PublicKey := ed25519.PublicKey(b)

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			var payload []byte
			var footer []byte
			if ver, err := Parse(test.token, &payload, &footer, symmetricKey, map[Version]crypto.PublicKey{Version1: rsaPublicKey, Version2: v2PublicKey}); assert.NoError(t, err) {
				assert.Equal(t, test.version, ver)
				assert.Equal(t, test.payload, payload)
				assert.Equal(t, test.footer, footer)
			}
		})
	}
}

func TestParse_Err(t *testing.T) {
	cases := map[string]struct {
		token string
		error error
	}{
		"Incorrect token format": {
			token: "v1.publiceqreqqereqrqerq",
			error: ErrIncorrectTokenFormat,
		},
		"Unsupported token version": {
			token: "v0.local.rElw-WywOuwAqKC9Yao3YokSp7vx",
			error: ErrUnsupportedTokenVersion,
		},
		"Unsupported token type": {
			token: "v1.private.rElw",
			error: ErrUnsupportedTokenType,
		},
		"Public key not found": {
			token: "v1.public.rElw",
			error: ErrPublicKeyNotFound,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(test.token, nil, nil, nil, nil)
			assert.Equal(t, test.error, err)
		})
	}

}

func TestParseFooter(t *testing.T) {
	cases := map[string]struct {
		token   string
		footer  []byte
		version Version
		err     error
	}{
		"Non empty footer": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
			footer:  []byte("Cuon Alpinus"),
			version: Version1,
		},
		"Empty footer": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx",
			version: Version1,
		},
		"Incorrect token format": {
			token: "v1.rElw-WywOuwAqK",
			err:   ErrIncorrectTokenFormat,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			var footer []byte
			err := ParseFooter(test.token, &footer)
			assert.Equal(t, test.err, err)
			assert.Equal(t, test.footer, footer)
		})
	}
}

func TestGetTokenInfo(t *testing.T) {
	cases := map[string]struct {
		token   string
		version Version
		purpose Purpose
		err     error
	}{
		"v1.local": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
			version: Version1,
			purpose: LOCAL,
		},
		"v2.local": {
			token:   "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
			version: Version2,
			purpose: LOCAL,
		},
		"v1.public": {
			token:   "v1.public.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVh",
			version: Version1,
			purpose: PUBLIC,
		},
		"Unsupported token version": {
			token: "v0.public.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVh",
			err:   ErrUnsupportedTokenVersion,
		},
		"Unsupported token type": {
			token: "v1.private.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVh",
			err:   ErrUnsupportedTokenType,
		},
		"Incorrect token format": {
			token: "v1.private",
			err:   ErrIncorrectTokenFormat,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			version, purpose, err := GetTokenInfo(test.token)
			assert.Equal(t, test.err, err)
			assert.Equal(t, test.version, version)
			assert.Equal(t, test.purpose, purpose)
		})
	}
}
