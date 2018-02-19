package paseto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreAuth(t *testing.T) {
	b, _ := hex.DecodeString("0000000000000000")
	assert.Equal(t, b, preAuthEncode())

	b, _ = hex.DecodeString("01000000000000000000000000000000")
	assert.Equal(t, b, preAuthEncode([]byte{}))

	b, _ = hex.DecodeString("020000000000000000000000000000000000000000000000")
	assert.Equal(t, b, preAuthEncode([]byte{}, []byte{}))

	b, _ = hex.DecodeString("0100000000000000070000000000000050617261676f6e")
	assert.Equal(t, b, preAuthEncode([]byte("Paragon")))

	b, _ = hex.DecodeString("0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665")
	assert.Equal(t, b, preAuthEncode([]byte("Paragon"), []byte("Initiative")))
}
