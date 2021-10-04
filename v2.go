package paseto

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
	errors "golang.org/x/xerrors"
)

const (
	v2SignSize = ed25519.SignatureSize
	// XNonceSize is the size of the XChaCha20 nonce in bytes.
	XNonceSize                = 24
	v2SymmetricKeySize        = 32
	v2AsymmetricSecretKeySize = 64
	v2AsymmetricPublicKeySize = 32
)

var headerV2 = []byte("v2.local.")
var headerV2Public = []byte("v2.public.")

// NewV2 returns a v2 implementation of PASETO tokens.
func NewV2() *V2 {
	return &V2{}
}

// V2 is a v2 implementation of PASETO tokens
type V2 struct {
	// this property is used for testing purposes only
	nonce []byte
}

// V2SymmetricKey Version 2 Symmetric Key
type V2SymmetricKey struct {
	material []byte
}

// V2AsymmetricSecretKey Version 2 Private Key
type V2AsymmetricSecretKey struct {
	material ed25519.PrivateKey
}

// Public returns the public key corresponding to priv.
func (k V2AsymmetricSecretKey) Public() V2AsymmetricPublicKey {
	return V2AsymmetricPublicKey{material: k.material.Public().(ed25519.PublicKey)}
}

// V2AsymmetricPublicKey Version 2 Public Key
type V2AsymmetricPublicKey struct {
	material ed25519.PublicKey
}

// Encrypt implements Protocol.Encrypt
func (p *V2) Encrypt(key SymmetricKey, payload, footer interface{}) (string, error) {
	v2SymmetricKey, ok := key.(V2SymmetricKey)

	if !ok {
		return "", ErrWrongKeyType
	}

	return v2SymmetricKey.encrypt(payload, footer, p.nonce)
}

// Decrypt implements Protocol.Decrypt
func (p *V2) Decrypt(token string, key SymmetricKey, payload, footer interface{}) error {
	v2SymmetricKey, ok := key.(V2SymmetricKey)

	if !ok {
		return ErrWrongKeyType
	}

	return v2SymmetricKey.decrypt(token, payload, footer)
}

// Sign implements Protocol.Sign. privateKey should be of type *rsa.PrivateKey
func (p *V2) Sign(privateKey AsymmetricSecretKey, payload, footer interface{}) (string, error) {
	v2SecretKey, ok := privateKey.(V2AsymmetricSecretKey)

	if !ok {
		return "", ErrWrongKeyType
	}

	return v2SecretKey.sign(payload, footer)
}

// Verify implements Protocol.Verify. publicKey should be of type *rsa.PublicKey
func (p *V2) Verify(token string, publicKey AsymmetricPublicKey, payload, footer interface{}) error {
	v2PublicKey, ok := publicKey.(V2AsymmetricPublicKey)

	if !ok {
		return ErrWrongKeyType
	}

	return v2PublicKey.verify(token, payload, footer)
}

// encrypt implements SymmetricKey.encrypt
func (k V2SymmetricKey) encrypt(payload, footer interface{}, unitTestNonce []byte) (string, error) {
	if len(k.material) != v2SymmetricKeySize {
		return "", ErrWrongKeyLength
	}

	payloadBytes, err := infToByteArr(payload)
	if err != nil {
		return "", errors.Errorf("failed to encode payload to []byte: %w", err)
	}

	footerBytes, err := infToByteArr(footer)
	if err != nil {
		return "", errors.Errorf("failed to encode footer to []byte: %w", err)
	}

	var rndBytes []byte

	if unitTestNonce != nil {
		rndBytes = unitTestNonce
	} else {
		rndBytes = make([]byte, XNonceSize)
		if _, err := io.ReadFull(rand.Reader, rndBytes); err != nil { //nolint:govet
			return "", errors.Errorf("failed to read from rand.Reader: %w", err)
		}
	}

	hash, err := blake2b.New(XNonceSize, rndBytes)
	if err != nil {
		return "", errors.Errorf("failed to create blake2b hash: %w", err)
	}
	if _, err := hash.Write(payloadBytes); err != nil { //nolint:govet
		return "", errors.Errorf("failed to hash payload: %w", err)
	}

	nonce := hash.Sum(nil)

	aead, err := chacha20poly1305.NewX(k.material[:])
	if err != nil {
		return "", errors.Errorf("failed to create chacha20poly1305 cipher: %w", err)
	}

	encryptedPayload := aead.Seal(payloadBytes[:0], nonce, payloadBytes, preAuthEncode(headerV2, nonce, footerBytes))

	return createToken(headerV2, append(nonce, encryptedPayload...), footerBytes), nil
}

// decrypt implements SymmetricKey.decrypt
func (k V2SymmetricKey) decrypt(token string, payload interface{}, footer interface{}) error {
	if len(k.material) != v2SymmetricKeySize {
		return ErrWrongKeyLength
	}

	body, footerBytes, err := splitToken([]byte(token), headerV2)
	if err != nil {
		return errors.Errorf("failed to decode token: %w", err)
	}

	if len(body) < XNonceSize {
		return errors.Errorf("incorrect token size: %w", ErrIncorrectTokenFormat)
	}

	nonce := body[:XNonceSize]
	encryptedPayload := body[XNonceSize:]

	aead, err := chacha20poly1305.NewX(k.material)
	if err != nil {
		return errors.Errorf("failed to create chacha20poly1305 cipher: %w", err)
	}

	decryptedPayload, err := aead.Open(encryptedPayload[:0], nonce, encryptedPayload, preAuthEncode(headerV2, nonce, footerBytes))
	if err != nil {
		return ErrInvalidTokenAuth
	}

	if payload != nil {
		if err := fillValue(decryptedPayload, payload); err != nil {
			return errors.Errorf("failed to decode payload: %w", err)
		}
	}

	if footer != nil {
		if err := fillValue(footerBytes, footer); err != nil {
			return errors.Errorf("failed to decode footer: %w", err)
		}
	}
	return nil
}

// sign implements AsymmetricSecretKey.sign
func (k V2AsymmetricSecretKey) sign(payload, footer interface{}) (string, error) {
	if len(k.material) != v2AsymmetricSecretKeySize {
		return "", ErrWrongKeyLength
	}

	payloadBytes, err := infToByteArr(payload)
	if err != nil {
		return "", errors.Errorf("failed to encode payload to []byte: %w", err)
	}

	footerBytes, err := infToByteArr(footer)
	if err != nil {
		return "", errors.Errorf("failed to encode footer to []byte: %w", err)
	}

	sig := ed25519.Sign(k.material, preAuthEncode(headerV2Public, payloadBytes, footerBytes))

	return createToken(headerV2Public, append(payloadBytes, sig...), footerBytes), nil
}

// verify implements AsymmetricPublicKey.verify
func (k V2AsymmetricPublicKey) verify(token string, payload, footer interface{}) error {
	if len(k.material) != v2AsymmetricPublicKeySize {
		return ErrWrongKeyLength
	}

	data, footerBytes, err := splitToken([]byte(token), headerV2Public)
	if err != nil {
		return errors.Errorf("failed to decode token: %w", err)
	}

	if len(data) < v2SignSize {
		return errors.Errorf("incorrect token size: %w", ErrIncorrectTokenFormat)
	}

	payloadBytes := data[:len(data)-v2SignSize]
	signature := data[len(data)-v2SignSize:]

	if !ed25519.Verify(k.material, preAuthEncode(headerV2Public, payloadBytes, footerBytes), signature) {
		return ErrInvalidSignature
	}

	if payload != nil {
		if err := fillValue(payloadBytes, payload); err != nil {
			return errors.Errorf("failed to decode payload: %w", err)
		}
	}

	if footer != nil {
		if err := fillValue(footerBytes, footer); err != nil {
			return errors.Errorf("failed to decode footer: %w", err)
		}
	}

	return nil
}
