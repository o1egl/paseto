package paseto

import (
	"crypto"
	"crypto/rand"
	"io"

	"github.com/aead/chacha20/chacha"
	"github.com/aead/chacha20poly1305"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

const (
	v2SignSize = ed25519.SignatureSize
)

var headerV2 = []byte("v2.local.")
var headerV2Public = []byte("v2.public.")

// NewV2 return V2 implementation on paseto tokens
func NewV2() Protocol {
	return &pasetoV2{}
}

type pasetoV2 struct {
}

// Encrypt implements Protocol.Encrypt
func (*pasetoV2) Encrypt(key []byte, value interface{}, opParams ...opsFunc) (string, error) {
	ops := options{}
	for _, op := range opParams {
		op(&ops)
	}

	var payload []byte
	var footer []byte
	var err error

	payload, err = infToByteArr(value)
	if err != nil {
		return "", err
	}

	if ops.footer != nil {
		footer, err = infToByteArr(ops.footer)
		if err != nil {
			return "", err
		}
	}

	var rndBytes []byte

	if ops.nonce != nil {
		rndBytes = ops.nonce
	} else {
		rndBytes = make([]byte, chacha.XNonceSize)
		if _, err := io.ReadFull(rand.Reader, rndBytes); err != nil {
			return "", err
		}
	}

	hash, err := blake2b.New(chacha.XNonceSize, rndBytes)
	if err != nil {
		return "", err
	}
	if _, err := hash.Write(payload); err != nil {
		return "", err
	}

	nonce := hash.Sum(nil)

	aead, err := chacha20poly1305.NewXCipher(key)
	if err != nil {
		return "", err
	}

	encryptedPayload := aead.Seal(payload[:0], nonce, payload, preAuthEncode(headerV2, nonce, footer))

	return createToken(headerV2, append(nonce, encryptedPayload...), footer), nil
}

// Decrypt implements Protocol.Decrypt
func (*pasetoV2) Decrypt(token string, key []byte, payload interface{}, footer interface{}) error {
	body, footerBytes, err := splitToken([]byte(token), headerV2)
	if err != nil {
		return err
	}

	if len(body) < chacha.XNonceSize {
		return ErrIncorrectTokenFormat
	}

	nonce := body[:chacha.XNonceSize]
	encryptedPayload := body[chacha.XNonceSize:]

	aead, err := chacha20poly1305.NewXCipher(key)
	if err != nil {
		return err
	}

	decryptedPayload, err := aead.Open(encryptedPayload[:0], nonce, encryptedPayload, preAuthEncode(headerV2, nonce, footerBytes))
	if err != nil {
		return ErrInvalidTokenAuth
	}

	if payload != nil {
		if err := fillValue(decryptedPayload, payload); err != nil {
			return err
		}
	}

	if footer != nil {
		if err := fillValue(footerBytes, footer); err != nil {
			return err
		}
	}
	return nil
}

// Sign implements Protocol.Sign
func (*pasetoV2) Sign(privateKey crypto.PrivateKey, value interface{}, params ...opsFunc) (string, error) {
	priv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return "", ErrIncorrectPrivateKeyType
	}

	ops := options{}
	for _, op := range params {
		op(&ops)
	}

	var payload []byte
	var footer []byte
	var err error

	payload, err = infToByteArr(value)
	if err != nil {
		return "", err
	}

	if ops.footer != nil {
		footer, err = infToByteArr(ops.footer)
		if err != nil {
			return "", err
		}
	}

	sig := ed25519.Sign(priv, preAuthEncode(headerV2Public, payload, footer))

	return createToken(headerV2Public, append(payload, sig...), footer), nil
}

// Decrypt implements Protocol.Verify
func (*pasetoV2) Verify(token string, publicKey crypto.PublicKey, value interface{}, footer interface{}) error {
	pub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return ErrIncorrectPublicKeyType
	}

	data, footerBytes, err := splitToken([]byte(token), headerV2Public)
	if err != nil {
		return err
	}

	if len(data) < v2SignSize {
		return ErrIncorrectTokenFormat
	}

	payload := data[:len(data)-v2SignSize]
	signatute := data[len(data)-v2SignSize:]

	if !ed25519.Verify(pub, preAuthEncode(headerV2Public, payload, footerBytes), signatute) {
		return ErrInvalidSignature
	}

	if value != nil {
		if err := fillValue(payload, value); err != nil {
			return err
		}
	}

	if footer != nil {
		if err := fillValue(footerBytes, footer); err != nil {
			return err
		}
	}

	return nil
}
