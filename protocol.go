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

// WithFooter adds an optional footer to the token. The footer is always included as plaintext,
// base64 encoded.
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

// Protocol defines the PASETO token protocol interface.
type Protocol interface {

	// Encrypt encrypts a token with a symmetric key. The key should be a byte
	// slice of 32 bytes, regardless of whether PASETO v1 or v2 is being used.
	Encrypt(key []byte, payload interface{}, options ...opsFunc) (string, error)

	// Decrypt decrypts a token which was encrypted with a symmetric key.
	Decrypt(token string, key []byte, payload interface{}, footer interface{}) error

	// Sign signs a token with the given private key. For PASETO v1, the key should
	// be an rsa.PrivateKey. For v2, the key should be an ed25519.PrivateKey.
	Sign(privateKey crypto.PrivateKey, payload interface{}, options ...opsFunc) (string, error)

	// Verify verifies a token against the given public key. For PASETO v1, the key
	// key should be an rsa.PublicKey. For v2, the key should be an
	// ed25519.PublicKey.
	Verify(token string, publicKey crypto.PublicKey, value interface{}, footer interface{}) error
}
