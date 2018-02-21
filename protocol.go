package paseto

import (
	"crypto"
	"errors"
)

var (
	// ErrUnsupportedTokenVersion unsupported parser version
	ErrUnsupportedTokenVersion = errors.New("unsupported parser version")
	// ErrUnsupportedTokenType unsupported token type
	ErrUnsupportedTokenType = errors.New("unsupported token type")
	// ErrIncorrectPrivateKeyType incorrect private key type
	ErrIncorrectPrivateKeyType = errors.New("incorrect private key type")
	// ErrIncorrectPublicKeyType incorrect public key type
	ErrIncorrectPublicKeyType = errors.New("incorrect public key type")
	// ErrPublicKeyNotFound public key for this version not found
	ErrPublicKeyNotFound = errors.New("public key for this version not found")
	// ErrIncorrectTokenFormat incorrect token format
	ErrIncorrectTokenFormat = errors.New("incorrect token format")
	// ErrIncorrectTokenHeader incorrect token header
	ErrIncorrectTokenHeader = errors.New("incorrect token header")
	// ErrInvalidTokenAuth invalid token authentication
	ErrInvalidTokenAuth = errors.New("invalid token authentication")
	// ErrInvalidSignature invalid signature
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrDataUnmarshal can't unmarshal token data to the given type of value
	ErrDataUnmarshal = errors.New("can't unmarshal token data to the given type of value")
)

type opsFunc func(ops *options)

type options struct {
	footer interface{}
	nonce  []byte
}

// WithFooter adds footer to the token
func WithFooter(footer interface{}) func(*options) {
	return func(c *options) {
		c.footer = footer
	}
}

func withNonce(nonce []byte) func(*options) {
	return func(c *options) {
		c.nonce = nonce
	}
}

// Protocol defines PASETO tokes protocol
type Protocol interface {
	// Encrypt encrypts token with symmetric key
	Encrypt(key []byte, payload interface{}, options ...opsFunc) (string, error)
	// Decrypt decrypts key encrypted with symmetric key
	Decrypt(token string, key []byte, payload interface{}, footer interface{}) error
	// Sign signs token with given private key
	Sign(privateKey crypto.PrivateKey, payload interface{}, options ...opsFunc) (string, error)
	// Verify verifies token with given public key
	Verify(token string, publicKey crypto.PublicKey, value interface{}, footer interface{}) error
}
