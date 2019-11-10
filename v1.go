package paseto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"io"

	errors "golang.org/x/xerrors"
)

const (
	nonceSize  = 32
	macSize    = 48
	v1SignSize = 256
)

var headerV1 = []byte("v1.local.")
var headerV1Public = []byte("v1.public.")

var tokenEncoder = base64.RawURLEncoding

// V1 is a v1 implementation of PASETO tokens
type V1 struct {
	// this property is used for testing purposes only
	nonce []byte
}

// NewV1 returns a v1 implementation of PASETO tokens.
// You should not use PASETO v1 unless you need interoperability with for legacy
// systems that cannot use modern cryptography.
func NewV1() *V1 {
	return &V1{}
}

// Encrypt implements Protocol.Encrypt
func (p *V1) Encrypt(key []byte, payload, footer interface{}) (string, error) {
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
		rndBytes = make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, rndBytes); err != nil { //nolint:govet
			return "", errors.Errorf("failed to read from rand.Reader: %w", err)
		}
	}

	macN := hmac.New(sha512.New384, rndBytes)
	if _, err := macN.Write(payloadBytes); err != nil { //nolint:govet
		return "", errors.Errorf("failed to hash payload: %w", err)
	}
	nonce := macN.Sum(nil)[:32]

	encKey, authKey, err := splitKey(key, nonce[:16])
	if err != nil {
		return "", errors.Errorf("failed to create enc and auth keys: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", errors.Errorf("failed to create aes cipher: %w", err)
	}

	encryptedPayload := make([]byte, len(payloadBytes))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(encryptedPayload, payloadBytes)

	h := hmac.New(sha512.New384, authKey)
	if _, err := h.Write(preAuthEncode(headerV1, nonce, encryptedPayload, footerBytes)); err != nil {
		return "", errors.Errorf("failed to create a signature: %w", err)
	}

	mac := h.Sum(nil)

	body := make([]byte, 0, len(nonce)+len(encryptedPayload)+len(mac))
	body = append(body, nonce...)
	body = append(body, encryptedPayload...)
	body = append(body, mac...)

	return createToken(headerV1, body, footerBytes), nil
}

// Decrypt implements Protocol.Decrypt
func (p *V1) Decrypt(token string, key []byte, payload, footer interface{}) error {
	data, footerBytes, err := splitToken([]byte(token), headerV1)
	if err != nil {
		return errors.Errorf("failed to decode token: %w", err)
	}

	if len(data) < nonceSize+macSize {
		return ErrIncorrectTokenFormat
	}

	nonce := data[:nonceSize]
	encryptedPayload := data[nonceSize : len(data)-(macSize)]
	mac := data[len(data)-macSize:]

	encKey, authKey, err := splitKey(key, nonce[:16])
	if err != nil {
		return errors.Errorf("failed to create enc and auth keys: %w", err)
	}

	h := hmac.New(sha512.New384, authKey)
	if _, err := h.Write(preAuthEncode(headerV1, nonce, encryptedPayload, footerBytes)); err != nil { //nolint:govet
		return errors.Errorf("failed to create a signature: %w", err)
	}

	if !hmac.Equal(h.Sum(nil), mac) {
		return errors.Errorf("failed to check token signature: %w", ErrInvalidTokenAuth)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return errors.Errorf("failed to create aes cipher: %w", err)
	}
	decryptedPayload := make([]byte, len(encryptedPayload))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(decryptedPayload, encryptedPayload)

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

// Sign implements Protocol.Sign. privateKey should be of type *rsa.PrivateKey
func (p *V1) Sign(privateKey crypto.PrivateKey, payload, footer interface{}) (string, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
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

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	PSSMessage := preAuthEncode(headerV1Public, payloadBytes, footerBytes)
	sha384 := crypto.SHA384
	pssHash := sha384.New()
	if _, err := pssHash.Write(PSSMessage); err != nil { //nolint:govet
		return "", errors.Errorf("failed to create pss hash: %w", err)
	}
	hashed := pssHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, sha384, hashed, &opts)
	if err != nil {
		return "", errors.Errorf("failed to sign token: %w", err)
	}

	body := append(payloadBytes, signature...)

	return createToken(headerV1Public, body, footerBytes), nil
}

// Verify implements Protocol.Verify. publicKey should be of type *rsa.PublicKey
func (p *V1) Verify(token string, publicKey crypto.PublicKey, payload, footer interface{}) error {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return ErrIncorrectPublicKeyType
	}

	data, footerBytes, err := splitToken([]byte(token), headerV1Public)
	if err != nil {
		return errors.Errorf("failed to decode token: %w", err)
	}

	if len(data) < v1SignSize {
		return errors.Errorf("incorrect signature size: %w", ErrIncorrectTokenFormat)
	}

	payloadBytes := data[:len(data)-v1SignSize]
	signature := data[len(data)-v1SignSize:]

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	PSSMessage := preAuthEncode(headerV1Public, payloadBytes, footerBytes)
	sha384 := crypto.SHA384
	pssHash := sha384.New()
	if _, err := pssHash.Write(PSSMessage); err != nil { //nolint:govet
		return errors.Errorf("failed to create pss hash: %w", err)
	}
	hashed := pssHash.Sum(nil)

	if err = rsa.VerifyPSS(rsaPublicKey, sha384, hashed, signature, &opts); err != nil {
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
