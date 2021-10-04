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

	"golang.org/x/crypto/hkdf"
	errors "golang.org/x/xerrors"
)

const (
	nonceSize          = 32
	macSize            = 48
	v1SignSize         = 256
	v1SymmetricKeySize = 32
)

var headerV1 = []byte("v1.local.")
var headerV1Public = []byte("v1.public.")

var tokenEncoder = base64.RawURLEncoding

// V1 is a v1 implementation of PASETO tokens
type V1 struct {
	// this property is used for testing purposes only
	nonce []byte
}

// V1SymmetricKey Version 1 Symmetric Key
type V1SymmetricKey struct {
	material []byte
}

// V1AsymmetricSecretKey Version 1 Private Key
type V1AsymmetricSecretKey struct {
	material rsa.PrivateKey
}

// Public returns the public key corresponding to priv.
func (k V1AsymmetricSecretKey) Public() V1AsymmetricPublicKey {
	return V1AsymmetricPublicKey{material: k.material.Public().(rsa.PublicKey)}
}

// V1AsymmetricPublicKey Version 1 Public Key
type V1AsymmetricPublicKey struct {
	material rsa.PublicKey
}

// NewV1 returns a v1 implementation of PASETO tokens.
// You should not use PASETO v1 unless you need interoperability with for legacy
// systems that cannot use modern cryptography.
func NewV1() *V1 {
	return &V1{}
}

// Encrypt implements Protocol.Encrypt
func (p *V1) Encrypt(key SymmetricKey, payload, footer interface{}) (string, error) {
	v1SymmetricKey, ok := key.(V1SymmetricKey)

	if !ok {
		return "", ErrWrongKeyType
	}

	return v1SymmetricKey.encrypt(payload, footer, p.nonce)
}

// Decrypt implements Protocol.Decrypt
func (p *V1) Decrypt(token string, key SymmetricKey, payload, footer interface{}) error {
	v1SymmetricKey, ok := key.(V1SymmetricKey)

	if !ok {
		return ErrWrongKeyType
	}

	return v1SymmetricKey.decrypt(token, payload, footer)
}

// Sign implements Protocol.Sign. privateKey should be of type *rsa.PrivateKey
func (p *V1) Sign(privateKey AsymmetricSecretKey, payload, footer interface{}) (string, error) {
	v1SecretKey, ok := privateKey.(V1AsymmetricSecretKey)

	if !ok {
		return "", ErrWrongKeyType
	}

	return v1SecretKey.sign(payload, footer)
}

// Verify implements Protocol.Verify. publicKey should be of type *rsa.PublicKey
func (p *V1) Verify(token string, publicKey AsymmetricPublicKey, payload, footer interface{}) error {
	v1PublicKey, ok := publicKey.(V1AsymmetricPublicKey)

	if !ok {
		return ErrWrongKeyType
	}

	return v1PublicKey.verify(token, payload, footer)
}

func (k *V1SymmetricKey) split(salt []byte) (encKey, authKey []byte, err error) {
	eReader := hkdf.New(sha512.New384, k.material[:], salt, []byte("paseto-encryption-key"))
	aReader := hkdf.New(sha512.New384, k.material[:], salt, []byte("paseto-auth-key-for-aead"))
	encKey = make([]byte, 32)
	authKey = make([]byte, 32)
	if _, err = io.ReadFull(eReader, encKey); err != nil {
		return nil, nil, err
	}
	if _, err = io.ReadFull(aReader, authKey); err != nil {
		return nil, nil, err
	}

	return encKey, authKey, nil
}

// encrypt implements SymmetricKey.encrypt
func (k V1SymmetricKey) encrypt(payload, footer interface{}, unitTestNonce []byte) (string, error) {
	if len(k.material) != v1SymmetricKeySize {
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

	encKey, authKey, err := k.split(nonce[:16])
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

// decrypt implements SymmetricKey.decrypt
func (k V1SymmetricKey) decrypt(token string, payload interface{}, footer interface{}) error {
	if len(k.material) != v1SymmetricKeySize {
		return ErrWrongKeyLength
	}

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

	encKey, authKey, err := k.split(nonce[:16])
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

// sign implements AsymmetricSecretKey.sign
func (k V1AsymmetricSecretKey) sign(payload, footer interface{}) (string, error) {
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

	signature, err := rsa.SignPSS(rand.Reader, &k.material, sha384, hashed, &opts)
	if err != nil {
		return "", errors.Errorf("failed to sign token: %w", err)
	}

	body := append(payloadBytes, signature...)

	return createToken(headerV1Public, body, footerBytes), nil
}

// verify implements AsymmetricPublicKey.verify
func (k V1AsymmetricPublicKey) verify(token string, payload, footer interface{}) error {
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

	if err = rsa.VerifyPSS(&k.material, sha384, hashed, signature, &opts); err != nil {
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
