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

// NewV2 returns a v2 implementation of PASETO tokens.
func NewV2() *PasetoV2 {
	return &PasetoV2{}
}

type PasetoV2 struct {
	// this property is used for testing purposes only
	nonce []byte
}

// Encrypt implements Protocol.Encrypt
func (p *PasetoV2) Encrypt(key []byte, payload interface{}, footer interface{}) (string, error) {
	payloadBytes, err := infToByteArr(payload)
	if err != nil {
		return "", err
	}

	footerBytes, err := infToByteArr(footer)
	if err != nil {
		return "", err
	}

	var rndBytes []byte

	if p.nonce != nil {
		rndBytes = p.nonce
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
	if _, err := hash.Write(payloadBytes); err != nil {
		return "", err
	}

	nonce := hash.Sum(nil)

	aead, err := chacha20poly1305.NewXCipher(key)
	if err != nil {
		return "", err
	}

	encryptedPayload := aead.Seal(payloadBytes[:0], nonce, payloadBytes, preAuthEncode(headerV2, nonce, footerBytes))

	return createToken(headerV2, append(nonce, encryptedPayload...), footerBytes), nil
}

// Decrypt implements Protocol.Decrypt
func (*PasetoV2) Decrypt(token string, key []byte, payload interface{}, footer interface{}) error {
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
func (*PasetoV2) Sign(privateKey crypto.PrivateKey, payload interface{}, footer interface{}) (string, error) {
	priv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return "", ErrIncorrectPrivateKeyType
	}

	payloadBytes, err := infToByteArr(payload)
	if err != nil {
		return "", err
	}

	footerBytes, err := infToByteArr(footer)
	if err != nil {
		return "", err
	}

	sig := ed25519.Sign(priv, preAuthEncode(headerV2Public, payloadBytes, footerBytes))

	return createToken(headerV2Public, append(payloadBytes, sig...), footerBytes), nil
}

// Verify implements Protocol.Verify
func (*PasetoV2) Verify(token string, publicKey crypto.PublicKey, payload interface{}, footer interface{}) error {
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

	payloadBytes := data[:len(data)-v2SignSize]
	signature := data[len(data)-v2SignSize:]

	if !ed25519.Verify(pub, preAuthEncode(headerV2Public, payloadBytes, footerBytes), signature) {
		return ErrInvalidSignature
	}

	if payload != nil {
		if err := fillValue(payloadBytes, payload); err != nil {
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
