// Package oauth 提供了仅在单元测试中使用的辅助工具。
//
// 本文件定义了 TestKey，它是对所生成 RSA 密钥对的轻量封装，
// 提供了若干便捷方法用于生成 JWK 兼容的值（模数、指数、指纹），
// 同时不会将生产代码泄漏到最终二进制文件中。
package oauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// b64 是 JOSE 风格的 base64url 编码（无填充）。
var b64 = base64.RawURLEncoding

// TestKey 表示一个内存中的 RSA 密钥对，并提供了一些
// 用于简化 JWT 与 JWKS 相关单元测试的辅助方法。
type TestKey struct {
	priv *rsa.PrivateKey
	kid  string
}

// NewTestKey 生成一副指定长度的新 RSA 密钥对，
// 并立即计算其 RFC 7638 指纹，将结果缓存在 TestKey 实例中。
func NewTestKey(bits int) (*TestKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	// 为新公钥计算 RFC 7638 SHA‑256 指纹。
	eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
	jwk := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		b64.EncodeToString(eBytes),
		b64.EncodeToString(priv.N.Bytes()))
	sum := sha256.Sum256([]byte(jwk))

	return &TestKey{
		priv: priv,
		kid:  b64.EncodeToString(sum[:]),
	}, nil
}

// Private 返回 TestKey 关联的 *rsa.PrivateKey，
// 以便调用方直接签发 JSON Web Token。
func (k *TestKey) Private() *rsa.PrivateKey { return k.priv }

// Public 返回 RSA 密钥的公钥部分。该值可被嵌入
// JWKS 文档中，用于令牌校验。
func (k *TestKey) Public() *rsa.PublicKey { return &k.priv.PublicKey }

// ExponentString 使用无填充的 base64url 对公钥指数进行编码，
// 符合 JWK "e" 字段所要求的表示形式。
func (k *TestKey) ExponentString() string {
	eBytes := big.NewInt(int64(k.Public().E)).Bytes()
	return b64.EncodeToString(eBytes)
}

// ModulusString 使用无填充的 base64url 对模数进行编码，
// 这正是 JWK "n" 字段所期望的形式。
func (k *TestKey) ModulusString() string {
	return b64.EncodeToString(k.Public().N.Bytes())
}

// KID 返回该密钥预先计算好的 RFC 7638 指纹。
func (k *TestKey) KID() string { return k.kid }
