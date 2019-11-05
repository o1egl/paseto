package paseto

import (
	"crypto"
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
	XNonceSize = 24
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

// Encrypt implements Protocol.Encrypt
func (p *V2) Encrypt(key []byte, payload interface{}, footer interface{}) (string, error) {
	payloadBytes, err := infToByteArr(payload)
	if err != nil {
		return "", errors.Errorf("failed to encode payload to []byte: %w", err)
	}

	footerBytes, err := infToByteArr(footer)
	if err != nil {
		return "", errors.Errorf("failed to encode footer to []byte: %w", err)
	}

	var rndBytes []byte

	if p.nonce != nil {
		rndBytes = p.nonce
	} else {
		rndBytes = make([]byte, XNonceSize)
		if _, err := io.ReadFull(rand.Reader, rndBytes); err != nil {
			return "", errors.Errorf("failed to read from rand.Reader: %w", err)
		}
	}

	hash, err := blake2b.New(XNonceSize, rndBytes)
	if err != nil {
		return "", errors.Errorf("failed to create blake2b hash: %w", err)
	}
	if _, err := hash.Write(payloadBytes); err != nil {
		return "", errors.Errorf("failed to hash payload: %w", err)
	}

	nonce := hash.Sum(nil)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", errors.Errorf("failed to create chacha20poly1305 cipher: %w", err)
	}

	encryptedPayload := aead.Seal(payloadBytes[:0], nonce, payloadBytes, preAuthEncode(headerV2, nonce, footerBytes))

	return createToken(headerV2, append(nonce, encryptedPayload...), footerBytes), nil
}

// Decrypt implements Protocol.Decrypt
func (*V2) Decrypt(token string, key []byte, payload interface{}, footer interface{}) error {
	body, footerBytes, err := splitToken([]byte(token), headerV2)
	if err != nil {
		return errors.Errorf("failed to decode token: %w", err)
	}

	if len(body) < XNonceSize {
		return errors.Errorf("incorrect token size: %w", ErrIncorrectTokenFormat)
	}

	nonce := body[:XNonceSize]
	encryptedPayload := body[XNonceSize:]

	aead, err := chacha20poly1305.NewX(key)
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

// Sign implements Protocol.Sign
func (*V2) Sign(privateKey crypto.PrivateKey, payload interface{}, footer interface{}) (string, error) {
	key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return "", ErrIncorrectPrivateKeyType
	}

	payloadBytes, err := infToByteArr(payload)
	if err != nil {
		return "", errors.Errorf("failed to encode payload to []byte: %w", err)
	}

	footerBytes, err := infToByteArr(footer)
	if err != nil {
		return "", errors.Errorf("failed to encode footer to []byte: %w", err)
	}

	sig := ed25519.Sign(key, preAuthEncode(headerV2Public, payloadBytes, footerBytes))

	return createToken(headerV2Public, append(payloadBytes, sig...), footerBytes), nil
}

// Verify implements Protocol.Verify
func (*V2) Verify(token string, publicKey crypto.PublicKey, payload interface{}, footer interface{}) error {
	pub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return ErrIncorrectPublicKeyType
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

	if !ed25519.Verify(pub, preAuthEncode(headerV2Public, payloadBytes, footerBytes), signature) {
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
