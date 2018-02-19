package paseto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"io"

	"crypto"
	"crypto/rsa"
)

const (
	nonceSize = 32
	macSize   = 48
	signSize  = 256
)

var headerV1 = []byte("v1.local.")
var headerV1Public = []byte("v1.public.")

var tokenEncoder = base64.RawURLEncoding

type pasetoV1 struct {
}

// NewV1 return V1 implementation on paseto tokens
func NewV1() Protocol {
	return &pasetoV1{}
}

// Encrypt implements Protocol.Encrypt
func (p *pasetoV1) Encrypt(key []byte, value interface{}, ops ...opsFunc) (string, error) {
	options := options{}
	for _, op := range ops {
		op(&options)
	}

	var payload []byte
	var footer []byte
	var err error

	payload, err = infToByteArr(value)
	if err != nil {
		return "", err
	}

	if options.footer != nil {
		footer, err = infToByteArr(options.footer)
		if err != nil {
			return "", err
		}
	}

	var rndBytes []byte

	if options.nonce != nil {
		rndBytes = options.nonce
	} else {
		rndBytes = make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, rndBytes); err != nil {
			return "", err
		}
	}

	macN := hmac.New(sha512.New384, rndBytes)
	if _, err := macN.Write(payload); err != nil {
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

	encryptedPayload := make([]byte, len(payload))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(encryptedPayload, payload)

	h := hmac.New(sha512.New384, authKey)
	if _, err := h.Write(preAuthEncode(headerV1, nonce, encryptedPayload, footer)); err != nil {
		return "", err
	}

	mac := h.Sum(nil)

	d := make([]byte, 0, len(nonce)+len(encryptedPayload)+len(mac))
	d = append(d, nonce...)
	d = append(d, encryptedPayload...)
	d = append(d, mac...)

	encodedPayload := make([]byte, tokenEncoder.EncodedLen(len(d)))
	tokenEncoder.Encode(encodedPayload, d)

	footerLen := 0
	var encodedFooter []byte
	if footer != nil {
		encodedFooter = make([]byte, tokenEncoder.EncodedLen(len(footer)))
		tokenEncoder.Encode(encodedFooter, footer)
		footerLen = len(encodedFooter) + 1
	}

	response := make([]byte, len(headerV1)+len(encodedPayload)+footerLen)
	offset := 0
	offset += copy(response[offset:], headerV1)
	offset += copy(response[offset:], encodedPayload)
	if encodedFooter != nil {
		offset += copy(response[offset:], []byte("."))
		copy(response[offset:], encodedFooter)

	}
	return string(response), nil
}

// Encrypt implements Protocol.Decrypt
func (p *pasetoV1) Decrypt(token string, key []byte, value interface{}, footer interface{}) error {
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
		return ErrInvalidMAC
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	decryptedPayload := make([]byte, len(encryptedPayload))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(decryptedPayload, encryptedPayload)

	if value != nil {
		if err := fillValue(decryptedPayload, value); err != nil {
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

// Encrypt implements Protocol.Sign. privateKey should be of type *rsa.PrivateKey
func (p *pasetoV1) Sign(privateKey crypto.PrivateKey, value interface{}, params ...opsFunc) (string, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", ErrIncorrectPrivateKey
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

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	PSSmessage := preAuthEncode(headerV1Public, payload, footer)
	newhash := crypto.SHA384
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, newhash, hashed, &opts)
	if err != nil {
		panic(err)
	}

	data := append(payload, signature...)

	encodedPayload := make([]byte, tokenEncoder.EncodedLen(len(data)))
	tokenEncoder.Encode(encodedPayload, data)

	footerLen := 0
	var encodedFooter []byte
	if footer != nil {
		encodedFooter = make([]byte, tokenEncoder.EncodedLen(len(footer)))
		tokenEncoder.Encode(encodedFooter, footer)
		footerLen = len(encodedFooter) + 1
	}

	response := make([]byte, len(headerV1Public)+len(encodedPayload)+footerLen)
	offset := 0
	offset += copy(response[offset:], headerV1Public)
	offset += copy(response[offset:], encodedPayload)
	if encodedFooter != nil {
		offset += copy(response[offset:], []byte("."))
		copy(response[offset:], encodedFooter)

	}

	return string(response), nil
}

// Encrypt implements Protocol.Verify. publicKey should be of type *rsa.PublicKey
func (p *pasetoV1) Verify(token string, publicKey crypto.PublicKey, value interface{}, footer interface{}) error {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return ErrIncorrectPublicKey
	}

	data, footerBytes, err := splitToken([]byte(token), headerV1Public)
	if err != nil {
		return err
	}

	if len(data) < signSize {
		return ErrIncorrectTokenFormat
	}

	payload := data[:len(data)-signSize]
	signature := data[len(data)-signSize:]

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	PSSmessage := preAuthEncode(headerV1Public, payload, footerBytes)
	newhash := crypto.SHA384
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	if err = rsa.VerifyPSS(rsaPublicKey, newhash, hashed, signature, &opts); err != nil {
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
