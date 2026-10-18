package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type ctxKey string

const ctxOverwrite ctxKey = "zitadel-ctx-overwrite"

type cred struct {
	tokenSource oauth2.TokenSource
	tls         bool
}

// GetRequestMetadata 实现了 [credentials.PerRPCCredentials]。
// 它会检查上下文中是否显式设置了令牌，并将其用作授权凭据。
// 若未设置令牌，则检查是否存在以令牌来源形式提供的默认授权凭据可供使用。
func (c *cred) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	// 若显式设置了令牌，则使用它
	token, ok := ctx.Value(ctxOverwrite).(*oauth2.Token)
	if ok {
		return requestMetadataFromToken(token), nil
	}
	// 检查是否提供了默认的令牌来源
	if c.tokenSource != nil {
		return c.tokenFromTokenSource()
	}
	return nil, nil
}

// RequireTransportSecurity 实现了 [credentials.PerRPCCredentials]
func (c *cred) RequireTransportSecurity() bool {
	return c.tls
}

func (c *cred) tokenFromTokenSource() (map[string]string, error) {
	token, err := c.tokenSource.Token()
	if err != nil {
		return nil, err
	}
	return requestMetadataFromToken(token), nil
}

func requestMetadataFromToken(token *oauth2.Token) map[string]string {
	return map[string]string{
		"authorization": token.Type() + " " + token.AccessToken,
	}
}

func transportCredentials(domain string, withTLS bool, insecureSkipVerifyTLS bool) (credentials.TransportCredentials, error) {
	if !withTLS {
		return insecure.NewCredentials(), nil
	}
	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: insecureSkipVerifyTLS,
	}
	if insecureSkipVerifyTLS {
		return credentials.NewTLS(tlsConfig), nil
	}
	ca, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if ca == nil {
		ca = x509.NewCertPool()
	}
	tlsConfig.RootCAs = ca
	return credentials.NewTLS(tlsConfig), nil
}
