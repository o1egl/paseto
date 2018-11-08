package paseto

import (
	"encoding/hex"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

// JSONToken
func Benchmark_V2_JSONToken_Encrypt(b *testing.B) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	now := time.Now()
	exp := now.Add(24 * time.Hour)
	nbt := now

	jsonToken := JSONToken{
		Audience:   "test",
		Issuer:     "test_service",
		Jti:        "123",
		Subject:    "test_subject",
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}

	footer := "footer"

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Encrypt(symmetricKey, jsonToken, footer)
	}
}

func Benchmark_V2_JSONToken_Decrypt(b *testing.B) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	token := "v2.local.Ydp5u4gIRRR6u7Nvdb64qJs1W2wKSHNNEmi0LCnuZ9s-j74qrYu77tMzbUZvILPQE9Pl3OxPo246BUqQQ38YbZtQ2Stw8SJbvSbwF7npAjMkTx4leorq-bez8i9jLuyv7dHy8F4JaN8XxoNSpQdKI4Gn567sY-YxvBDTcEtM-VwRfe6vXHk_QG6pfil0hemk3zOAHPq0GxCA_uQnx6ggYN4mP_rqKdYV2P6Myf9nZmc-sw1hHCMSZegx6OH1nrKzvzMA9Y2ZO_tsg8IACz_wG2Mk.Zm9vdGVy"

	var jsonToken JSONToken
	var footer string

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Decrypt(token, symmetricKey, &jsonToken, &footer)
	}
}

func Benchmark_V2_JSONToken_Sign(b *testing.B) {
	bb, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	privateKey := ed25519.PrivateKey(bb)

	now := time.Now()
	exp := now.Add(24 * time.Hour)
	nbt := now

	jsonToken := JSONToken{
		Audience:   "test",
		Issuer:     "test_service",
		Jti:        "123",
		Subject:    "test_subject",
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}

	footer := "footer"

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Sign(privateKey, jsonToken, footer)
	}
}

func Benchmark_V2_JSONToken_Verify(b *testing.B) {
	bb, _ := hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	publicKey := ed25519.PublicKey(bb)
	token := "v2.public.eyJhdWQiOiJ0ZXN0IiwiZXhwIjoiMjAxOC0wMy0xMlQyMTo1Njo1MSswMTowMCIsImlhdCI6IjIwMTgtMDMtMTFUMjE6NTY6NTErMDE6MDAiLCJpc3MiOiJ0ZXN0X3NlcnZpY2UiLCJqdGkiOiIxMjMiLCJuYmYiOiIyMDE4LTAzLTExVDIxOjU2OjUxKzAxOjAwIiwic3ViIjoidGVzdF9zdWJqZWN0In24L0oWXbztBIdJYgAzsMqb2_0zDTNu65YRAOwn3Ux8tvepyynlYmAQB1yhvh6MIKl1BecuKmg1QzN2YRcGZi8O.Zm9vdGVy"

	var jsonToken JSONToken
	var footer string

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Verify(token, publicKey, &jsonToken, &footer)
	}
}

// String
func Benchmark_V2_String_Encrypt(b *testing.B) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	payload := "payload"
	footer := "footer"

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Encrypt(symmetricKey, payload, footer)
	}
}

func Benchmark_V2_String_Decrypt(b *testing.B) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	token := "v2.local.VxvYfYL-KSCBaNC8toZUWgoqYHveHjypGx87pqUi0e69gKNAApe3sVkAog30zAc.Zm9vdGVy"

	var payload string
	var footer string

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Decrypt(token, symmetricKey, &payload, &footer)
	}
}

func Benchmark_V2_String_Sign(b *testing.B) {
	bb, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	privateKey := ed25519.PrivateKey(bb)

	payload := "payload"

	footer := "footer"

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Sign(privateKey, payload, footer)
	}
}

func Benchmark_V2_String_Verify(b *testing.B) {
	bb, _ := hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	publicKey := ed25519.PublicKey(bb)
	token := "v2.public.cGF5bG9hZP9crS7uGme2zSTkJ3kiamT0u6jN4qhKhiS0IWNi0sx-pS62QYJEHijhQGsCWRZ3JnoIBmLj6tawpN2Xd050pQg.Zm9vdGVy"

	var payload string
	var footer string

	v2 := NewV2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v2.Verify(token, publicKey, &payload, &footer)
	}
}
