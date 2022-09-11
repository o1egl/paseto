package paseto

import (
	errors "golang.org/x/xerrors"
)

var (
	// ErrUnsupportedTokenVersion unsupported parser version
	ErrUnsupportedTokenVersion = errors.New("unsupported parser version")
	// ErrUnsupportedTokenType unsupported token type
	ErrUnsupportedTokenType = errors.New("unsupported token type")
	// ErrWrongKeyType incorrect key given for PASETO operation
	ErrWrongKeyType = errors.New("the given key is not intended for this version of PASETO")
	// ErrWrongKeyLength incorrect key given for PASETO operation
	ErrWrongKeyLength = errors.New("the given key is the wrong length for this type of key")
	// ErrPublicKeyNotFound public key for this version not found
	ErrPublicKeyNotFound = errors.New("public key for this version not found")
	// ErrSecretKeyNotFound public key for this version not found
	ErrSecretKeyNotFound = errors.New("secret key for this version not found")
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
	// ErrTokenValidationError invalid token data
	ErrTokenValidationError = errors.New("token validation error")
)

// SymmetricKey Generic Symmetric Key
type SymmetricKey interface {

	// Encrypt encrypts a token with a symmetric key.
	encrypt(payload interface{}, footer interface{}, unitTestNonce []byte) (string, error)

	// Decrypt decrypts a token which was encrypted with a symmetric key.
	decrypt(token string, payload interface{}, footer interface{}) error
}

// AsymmetricSecretKey Generic Asymmetric Private Key
type AsymmetricSecretKey interface {

	// Sign signs a token with the given private key
	sign(payload interface{}, footer interface{}) (string, error)
}

// AsymmetricPublicKey Generic Asymmetric Public Key
type AsymmetricPublicKey interface {

	// Verify verifies a token against the given public key
	verify(token string, value interface{}, footer interface{}) error
}

// Protocol defines the PASETO token protocol interface.
type Protocol interface {

	// Encrypt encrypts a token with a symmetric key
	Encrypt(key SymmetricKey, payload interface{}, footer interface{}) (string, error)

	// Decrypt decrypts a token which was encrypted with a symmetric key
	Decrypt(token string, key SymmetricKey, payload interface{}, footer interface{}) error

	// Sign signs a token with the given private key
	Sign(privateKey AsymmetricSecretKey, payload interface{}, footer interface{}) (string, error)

	// Verify verifies a token against the given public key
	Verify(token string, publicKey AsymmetricPublicKey, value interface{}, footer interface{}) error
}
