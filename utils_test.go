package paseto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreAuth(t *testing.T) {
	cases := map[string]struct {
		encoded string
		pieces  [][]byte
	}{
		"No data": {
			encoded: "0000000000000000",
		},
		"One empty element": {
			encoded: "01000000000000000000000000000000",
			pieces:  [][]byte{{}},
		},
		"Two empty elements": {
			encoded: "020000000000000000000000000000000000000000000000",
			pieces:  [][]byte{{}, {}},
		},
		"One non empty element": {
			encoded: "0100000000000000070000000000000050617261676f6e",
			pieces:  [][]byte{[]byte("Paragon")},
		},
		"Two non empty elements": {
			encoded: "0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
			pieces:  [][]byte{[]byte("Paragon"), []byte("Initiative")},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if b, err := hex.DecodeString(test.encoded); assert.NoError(t, err) {
				assert.Equal(t, b, preAuthEncode(test.pieces...))
			}
		})
	}
}
