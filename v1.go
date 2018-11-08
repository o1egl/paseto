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
)

const (
	nonceSize  = 32
	macSize    = 48
	v1SignSize = 256
)

var headerV1 = []byte("v1.local.")
var headerV1Public = []byte("v1.public.")

var tokenEncoder = base64.RawURLEncoding

type PasetoV1 struct {
	// this property is used for testing purposes only
	nonce []byte
}

// NewV1 returns a v1 implementation of PASETO tokens.
// You should not use PASETO v1 unless you need interoperability with for legacy
// systems that cannot use modern cryptography.
func NewV1() *PasetoV1 {
	return &PasetoV1{}
}

// Encrypt implements Protocol.Encrypt
func (p *PasetoV1) Encrypt(key []byte, payload interface{}, footer interface{}) (string, error) {
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
		rndBytes = make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, rndBytes); err != nil {
			return "", err
		}
	}

	macN := hmac.New(sha512.New384, rndBytes)
	if _, err := macN.Write(payloadBytes); err != nil {
		return "", err
	}
	nonce := macN.Sum(nil)[:32]

	encKey, authKey, err := splitKey(key, nonce[:16])
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}

	encryptedPayload := make([]byte, len(payloadBytes))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(encryptedPayload, payloadBytes)

	h := hmac.New(sha512.New384, authKey)
	if _, err := h.Write(preAuthEncode(headerV1, nonce, encryptedPayload, footerBytes)); err != nil {
		return "", err
	}

	mac := h.Sum(nil)

	body := make([]byte, 0, len(nonce)+len(encryptedPayload)+len(mac))
	body = append(body, nonce...)
	body = append(body, encryptedPayload...)
	body = append(body, mac...)

	return createToken(headerV1, body, footerBytes), nil
}

// Decrypt implements Protocol.Decrypt
func (p *PasetoV1) Decrypt(token string, key []byte, payload interface{}, footer interface{}) error {
	data, footerBytes, err := splitToken([]byte(token), headerV1)
	if err != nil {
		return err
	}

	if len(data) < nonceSize+macSize {
		return ErrIncorrectTokenFormat
	}

	nonce := data[:nonceSize]
	encryptedPayload := data[nonceSize : len(data)-(macSize)]
	mac := data[len(data)-macSize:]

	encKey, authKey, err := splitKey(key, nonce[:16])
	if err != nil {
		return err
	}

	h := hmac.New(sha512.New384, authKey)
	if _, err := h.Write(preAuthEncode(headerV1, nonce, encryptedPayload, footerBytes)); err != nil {
		return err
	}

	if !hmac.Equal(h.Sum(nil), mac) {
		return ErrInvalidTokenAuth
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	decryptedPayload := make([]byte, len(encryptedPayload))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(decryptedPayload, encryptedPayload)

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

// Sign implements Protocol.Sign. privateKey should be of type *rsa.PrivateKey
func (p *PasetoV1) Sign(privateKey crypto.PrivateKey, payload interface{}, footer interface{}) (string, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
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

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	PSSMessage := preAuthEncode(headerV1Public, payloadBytes, footerBytes)
	sha384 := crypto.SHA384
	pssHash := sha384.New()
	pssHash.Write(PSSMessage)
	hashed := pssHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, sha384, hashed, &opts)
	if err != nil {
		panic(err)
	}

	body := append(payloadBytes, signature...)

	return createToken(headerV1Public, body, footerBytes), nil
}

// Verify implements Protocol.Verify. publicKey should be of type *rsa.PublicKey
func (p *PasetoV1) Verify(token string, publicKey crypto.PublicKey, payload interface{}, footer interface{}) error {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return ErrIncorrectPublicKeyType
	}

	data, footerBytes, err := splitToken([]byte(token), headerV1Public)
	if err != nil {
		return err
	}

	if len(data) < v1SignSize {
		return ErrIncorrectTokenFormat
	}

	payloadBytes := data[:len(data)-v1SignSize]
	signature := data[len(data)-v1SignSize:]

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	PSSMessage := preAuthEncode(headerV1Public, payloadBytes, footerBytes)
	sha384 := crypto.SHA384
	pssHash := sha384.New()
	pssHash.Write(PSSMessage)
	hashed := pssHash.Sum(nil)

	if err = rsa.VerifyPSS(rsaPublicKey, sha384, hashed, signature, &opts); err != nil {
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
