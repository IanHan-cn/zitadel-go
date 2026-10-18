package oauth_test

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type signParams struct {
	KeyID      string
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Subject    string
	Audience   []string
	TTL        time.Duration
	NotBefore  time.Duration
	Algorithm  jwt.SigningMethod
}

// signTestJWT 仅供单元测试使用，用于构造一个可配置的已签名令牌。
func signTestJWT(p signParams) (string, error) {
	now := time.Now().UTC()

	claims := jwt.RegisteredClaims{
		Issuer:    p.Issuer,
		Subject:   p.Subject,
		Audience:  jwt.ClaimStrings(p.Audience),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(p.NotBefore)),
		ExpiresAt: jwt.NewNumericDate(now.Add(p.TTL)),
	}

	// 若未指定算法，则默认使用 RS256
	if p.Algorithm == nil {
		p.Algorithm = jwt.SigningMethodRS256
	}

	tok := jwt.NewWithClaims(p.Algorithm, claims)
	tok.Header["kid"] = p.KeyID

	// 处理 "none" 算法的情况，该算法不签名
	if p.Algorithm == jwt.SigningMethodNone {
		return tok.SigningString()
	}

	if p.PrivateKey == nil {
		return "", errors.New("private key is required for signing")
	}
	return tok.SignedString(p.PrivateKey)
}
