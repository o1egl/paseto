# Golang implementation of PASETO: Platform-Agnostic Security Tokens
[![License](http://img.shields.io/:license-mit-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/o1egl/paseto?status.svg)](https://godoc.org/github.com/o1egl/paseto)
[![Build Status](http://img.shields.io/travis/o1egl/paseto.svg?style=flat-square)](https://travis-ci.org/o1egl/paseto)
[![Coverage Status](http://img.shields.io/coveralls/o1egl/paseto.svg?style=flat-square)](https://coveralls.io/r/o1egl/paseto)
[![Go Report Card](https://goreportcard.com/badge/github.com/o1egl/paseto)](https://goreportcard.com/report/github.com/o1egl/paseto)

This is a 100% compatible pure Go (Golang) implementation of [PASETO](https://paseto.io) tokens.

PASETO is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

# Contents
* [What is PASETO?](#what-is-paseto)
  * [Key Differences between PASETO and JWT](#key-differences-between-paseto-and-jwt)
* [Installation](#installation)
* [Usage](#usage)
* [Benchmarks](#benchmarks)
* [Supported PASETO Versions](#supported-paseto-versions)

# What is PASETO?

PASETO (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation
for secure stateless tokens.

## Key Differences between PASETO and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, PASETO only allows secure operations. JWT gives you "algorithm agility",
PASETO gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use PASETO in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor PASETO were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> PASETO is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself.

### PASETO

#### PASETO Example 1

```
v2.local.QAxIpVe-ECVNI1z4xQbm_qQYomyT3h8FtV8bxkz8pBJWkT8f7HtlOpbroPDEZUKop_vaglyp76CzYy375cHmKCW8e1CCkV0Lflu4GTDyXMqQdpZMM1E6OaoQW27gaRSvWBrR3IgbFIa0AkuUFw.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz
```

This decodes to:

* Version: `v2`
* Purpose: `local` (shared-key authenticated encryption)
* Payload (hex-encoded):
  ```
  400c48a557be10254d235cf8c506e6fea418a26c93de1f05b55f1bc64cfca412
  56913f1fec7b653a96eba0f0c46542a8a7fbda825ca9efa0b3632dfbe5c1e628
  25bc7b5082915d0b7e5bb81930f25cca9076964c33513a39aa105b6ee06914af
  581ad1dc881b1486b4024b9417
  ```
  * Nonce: `400c48a557be10254d235cf8c506e6fea418a26c93de1f05`
  * Authentication tag: `6914af581ad1dc881b1486b4024b9417`
* Decrypted Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00+00:00"
  }
  ```
  * Key used in this example (hex-encoded):
    ```
    707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f  
    ``` 
* Footer:
  ```
  Paragon Initiative Enterprises
  ```

#### PASETO Example 2

```
v2.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZGF0YSI6InRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSJ91gC7-jCWsN3mv4uJaZxZp0btLJgcyVwL-svJD7f4IHyGteKe3HTLjHYTGHI1MtCqJ-ESDLNoE7otkIzamFskCA
```

This decodes to:

* Version: `v2`
* Purpose: `public` (public-key digital signature)
* Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00+00:00"
  }
  ```
* Signature (hex-encoded):
  ```
  d600bbfa3096b0dde6bf8b89699c59a746ed2c981cc95c0bfacbc90fb7f8207c
  86b5e29edc74cb8c761318723532d0aa27e1120cb36813ba2d908cda985b2408
  ```
* Public key (hex-encoded):
  ```
  11324397f535562178d53ff538e49d5a162242970556b4edd950c87c7d86648a
  ```

To learn what each version means, please see [this page in the documentation](https://github.com/paragonie/paseto/tree/master/docs/01-Protocol-Versions).

### JWT

An example JWT ([taken from JWT.io](https://jwt.io)) might look like this:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ 
```

This decodes to:

**Header**:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Body**:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

**Signature**:  
```
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

## Motivation 

As you can see, with JWT, you get to specify an `alg` header. There are a lot of options to
choose from (including `none`).

There have been ways to exploit JWT libraries by replacing RS256 with HS256 and using
the known public key as the HMAC-SHA256 key, thereby allowing arbitrary token forgery. 

With PASETO, your options are `version` and a `purpose`. There are two possible
values for `purpose`:

* `local` -- shared-key encryption (symmetric-key, [AEAD](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken))
* `public` -- public-key digital signatures (asymmetric-key)

PASETO only allows you to use [authenticated modes](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken).

Regardless of the purpose selected, the header (and an optional footer, which is always
cleartext but base64url-encoded) is included in the signature or authentication tag.

# Installation

To install the library use the following command:

```
$ go get -u github.com/o1egl/paseto
```

# Usage
This library contains a predefined JsonToken struct for using as payload, but you are free to use any data types and structs you want.

During the encoding process, a payload of type string and []byte is used without transformation. For other data types, the library encodes the payload to JSON.

## Create token using symmetric key (local mode): 
```go
symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY") // Must be 32 bytes
now := time.Now()
exp := now.Add(24 * time.Hour)
nbt := now

jsonToken := paseto.JSONToken{
        Audience:   "test",
        Issuer:     "test_service",
        Jti:        "123",
        Subject:    "test_subject",
        IssuedAt:   now,
        Expiration: exp,
        NotBefore:  nbt,
        }
// Add custom claim    to the token    
jsonToken.Set("data", "this is a signed message")
footer := "some footer"

// Encrypt data
token, err := paseto.Encrypt(symmetricKey, jsonToken, footer)
// token = "v2.local.E42A2iMY9SaZVzt-WkCi45_aebky4vbSUJsfG45OcanamwXwieieMjSjUkgsyZzlbYt82miN1xD-X0zEIhLK_RhWUPLZc9nC0shmkkkHS5Exj2zTpdNWhrC5KJRyUrI0cupc5qrctuREFLAvdCgwZBjh1QSgBX74V631fzl1IErGBgnt2LV1aij5W3hw9cXv4gtm_jSwsfee9HZcCE0sgUgAvklJCDO__8v_fTY7i_Regp5ZPa7h0X0m3yf0n4OXY9PRplunUpD9uEsXJ_MTF5gSFR3qE29eCHbJtRt0FFl81x-GCsQ9H9701TzEjGehCC6Bhw.c29tZSBmb290ZXI"

// Decrypt data
var newJsonToken paseto.JSONToken
var newFooter string
err := paseto.Decrypt(token, symmetricKey, &newJsonToken, &newFooter)
```

## Create token using asymetric key (public mode): 
```go
b, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
privateKey := ed25519.PrivateKey(b)

b, _ = hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
publicKey := ed25519.PublicKey(b)

// or create a new keypair 
// publicKey, privateKey, err := ed25519.GenerateKey(nil)

jsonToken := paseto.JSONToken{
        Expiration: time.Now().Add(24 * time.Hour),
        }
        
// Add custom claim    to the token    
jsonToken.Set("data", "this is a signed message")
footer := "some footer"

// Sign data
token, err := paseto.Sign(privateKey, jsonToken, footer)
// token = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOC0wMy0xMlQxOTowODo1NCswMTowMCJ9Ojv0uXlUNXSFhR88KXb568LheLRdeGy2oILR3uyOM_-b7r7i_fX8aljFYUiF-MRr5IRHMBcWPtM0fmn9SOd6Aw.c29tZSBmb290ZXI"

// Verify data
var newJsonToken paseto.JSONToken
var newFooter string
err := paseto.Verify(token, publicKey, &newJsonToken, &newFooter)
```

## Use Parse() function to parse all supported token versions:
**IMPORTANT**: Version 1 of the protocol is deprecated

```go
b, err := hex.DecodeString("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145417878636e47724e4f6136426c41523458707050640d0a746146576946386f7279746c4b534d6a66446831314c687956627a4335416967556b706a457274394d7649482f46384d444a72324f39486b36594b454b574b6f0d0a72333566364b6853303679357a714f722b7a4e34312b39626a52365633322b527345776d5a737a3038375258764e41334e687242633264593647736e57336c5a0d0a34356f5341564a755639553667335a334a574138355972362b6350776134793755632f56726f6d7a674679627355656e33476f724254626a783142384f514a440d0a73652f4b6b6855433655693358384264514f473974523455454775742f6c39703970732b3661474d4c57694357495a54615456784d4f75653133596b777038740d0a3148467635747a6872493055635948687638464a6b315a6435386759464158634e797975737834346e6a6152594b595948646e6b4f6a486e33416b534c4d306b0d0a6c774944415141420d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d")
block, _ := pem.Decode(b)
rsaPubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
v1PublicKey := rsaPubInterface.(*rsa.PublicKey)

b, _ = hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
v2PublicKey := ed25519.PublicKey(b)


var payload JSONToken
var footer string
version, err := paseto.Parse(token, &payload, &footer, symmetricKey, map[paseto.Version]crypto.PublicKey{paseto.V1: v1PublicKey, paseto.V2: v2PublicKey})
```

For more information see *_test.go files.

# Benchmarks
MacBook Pro (Retina, 15-inch, Late 2013)
CPU: 2,3 GHz Intel Core i7
RAM: 16 GB 1600 MHz DDR3
OS: macOS 10.14.1
GO: 1.11.2
```
$ go test -bench . -benchmem

Benchmark_V2_JSONToken_Encrypt-8          100000             11306 ns/op            5034 B/op         57 allocs/op
Benchmark_V2_JSONToken_Decrypt-8          100000             11795 ns/op            2848 B/op         60 allocs/op
Benchmark_V2_JSONToken_Sign-8              20000             71034 ns/op            4361 B/op         54 allocs/op
Benchmark_V2_JSONToken_Verify-8            10000            167387 ns/op            2416 B/op         57 allocs/op
Benchmark_V2_String_Encrypt-8             300000              3365 ns/op            2152 B/op         29 allocs/op
Benchmark_V2_String_Decrypt-8            1000000              1854 ns/op            1512 B/op         22 allocs/op
Benchmark_V2_String_Sign-8                 20000             60374 ns/op            1208 B/op         25 allocs/op
Benchmark_V2_String_Verify-8               10000            156859 ns/op             776 B/op         18 allocs/op
```

# Supported PASETO Versions
## Version 2
Version 2 (the recommended version by the specification) is fully supported.

## Version 1
Version 1 (the compatibility version) is fully supported.
