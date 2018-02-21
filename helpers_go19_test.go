// +build go1.9

package paseto

import (
	"crypto"
	"testing"
)

func testEncryptDecrypt(t *testing.T, impl Protocol) {
	t.Helper()
	_testEncryptDecrypt(t, impl)
}

func testSign(t *testing.T, impl Protocol, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	t.Helper()
	_testSign(t, impl, privateKey, publicKey)
}
