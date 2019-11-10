//go:generate go-enum --file $GOFILE
// Package paseto provides a Go implementation of PASETO, a secure alternative
// to the JOSE standards (JWT, JWE, JWS). See https://paseto.io/
package paseto

import (
	"crypto"
	"strings"

	errors "golang.org/x/xerrors"
)

// Version defines the token version.
/*
ENUM(
v1
v2
)
*/
type Version int

/*
ENUM(
local
public
)
*/
// Purpose defines the token type by its intended purpose.
type Purpose int

var availableVersions = map[Version]Protocol{
	VersionV1: NewV1(),
	VersionV2: NewV2(),
}

// Parse extracts the payload and footer from the token by calling either
// Decrypt() or Verify(), depending on whether the token is public or private.
// To parse public tokens you need to provide a map containing v1 and/or v2
// public keys, depending on the version of the token. To parse private tokens
// you need to provide the symmetric key.
func Parse(token string, payload, footer interface{},
	symmetricKey []byte, publicKeys map[Version]crypto.PublicKey) (Version, error) {
	parts := strings.Split(token, ".")
	version, err := ParseVersion(parts[0])
	if err != nil {
		return version, ErrUnsupportedTokenVersion
	}
	if len(parts) < 3 {
		return version, ErrIncorrectTokenFormat
	}

	protocol := availableVersions[version]

	purpose, err := ParsePurpose(parts[1])
	if err != nil {
		return version, ErrUnsupportedTokenType
	}
	switch purpose {
	case PurposeLocal:
		return version, protocol.Decrypt(token, symmetricKey, payload, footer)
	case PurposePublic:
		pubKey, found := publicKeys[version]
		if !found {
			return version, ErrPublicKeyNotFound
		}
		return version, protocol.Verify(token, pubKey, payload, footer)
	default:
		panic("unreachable")
	}
}

// ParseFooter parses the footer from the token and returns it.
func ParseFooter(token string, footer interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) == 4 {
		b, err := tokenEncoder.DecodeString(parts[3])
		if err != nil {
			return errors.Errorf("failed to decode token: %w", err)
		}
		if err := fillValue(b, footer); err != nil {
			return errors.Errorf("failed to decode footer: %w", err)
		}
	}
	if len(parts) < 3 {
		return ErrIncorrectTokenFormat
	}
	return nil
}

// GetTokenInfo returns the token version (paseto.VersionV1 or paseto.VersionV2) and purpose
// (paseto.PurposeLocal or paseto.PurposePublic).
func GetTokenInfo(token string) (Version, Purpose, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return 0, 0, ErrIncorrectTokenFormat
	}

	version, err := ParseVersion(parts[0])
	if err != nil {
		return 0, 0, ErrUnsupportedTokenVersion
	}

	purpose, err := ParsePurpose(parts[1])
	if err != nil {
		return 0, 0, ErrUnsupportedTokenType
	}

	return version, purpose, nil
}
