package paseto

import (
	"crypto"
	"strings"
)

// Version defines token version
type Version string

// Purpose defines token type
type Purpose int

const (
	// V1 defines protocol version 1
	V1 = Version("v1")
)

const (
	// LOCAL defines symmetric encrypted token type
	LOCAL Purpose = iota
	// PUBLIC defines asymmetric signed token type
	PUBLIC
)

var availableVersions = map[Version]Protocol{
	V1: NewV1(),
}

// Parse extracts payload and footer from token. To parse public tokens need to specify v1 and v2 public keys.
func Parse(token string, payload interface{}, footer interface{},
	symmetricKey []byte, publicKeys map[Version]crypto.PublicKey) (Version, error) {
	parts := strings.Split(token, ".")
	version := Version(parts[0])
	if len(parts) < 3 {
		return version, ErrIncorrectTokenFormat
	}

	protocol, found := availableVersions[version]
	if !found {
		return version, ErrUnsupportedTokenVersion
	}

	switch parts[1] {
	case "local":
		return version, protocol.Decrypt(token, symmetricKey, payload, footer)
	case "public":
		pubKey, found := publicKeys[version]
		if !found {
			return version, ErrPublicKeyNotFound
		}
		return version, protocol.Verify(token, pubKey, payload, footer)
	default:
		return version, ErrUnsupportedTokenType

	}
}

// ParseFooter parses footer from token
func ParseFooter(token string, footer interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) == 4 {
		b, err := tokenEncoder.DecodeString(parts[3])
		if err != nil {
			return err
		}
		return fillValue(b, footer)
	}
	if len(parts) < 3 {
		return ErrIncorrectTokenFormat
	}
	return nil
}

// GetTokenInfo returns token version and purpose
func GetTokenInfo(token string) (Version, Purpose, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return "", 0, ErrIncorrectTokenFormat
	}

	var version Version
	var purpose Purpose

	switch parts[0] {
	case string(V1):
		version = V1
	default:
		return "", 0, ErrUnsupportedTokenVersion
	}

	switch parts[1] {
	case "local":
		purpose = LOCAL
	case "public":
		purpose = PUBLIC
	default:
		return "", 0, ErrUnsupportedTokenType
	}

	return version, purpose, nil
}
