package zitadel

import (
	"fmt"
	"strconv"
)

// Zitadel 提供与你的 ZITADEL 实例进行交互的能力。
// 这包括认证、授权以及显式的 API 调用，
// 具体取决于所提供的信息及其初始化方式。
type Zitadel struct {
	domain                string
	port                  string
	tls                   bool
	insecureSkipVerifyTLS bool
	transportHeaders      map[string]string
}

func New(domain string, options ...Option) *Zitadel {
	zitadel := &Zitadel{
		domain:                domain,
		port:                  "443",
		tls:                   true,
		insecureSkipVerifyTLS: false,
		transportHeaders:      make(map[string]string),
	}
	for _, option := range options {
		option(zitadel)
	}
	return zitadel
}

// Option 用于对 [Zitadel] provider 进行定制。
type Option func(*Zitadel)

// WithInsecure 允许连接到未启用 TLS 的 ZITADEL 实例
// 请勿在生产环境中使用
func WithInsecure(port string) Option {
	return func(z *Zitadel) {
		z.port = port
		z.tls = false
	}
}

// WithInsecureSkipVerifyTLS 允许连接到启用了 TLS 但证书不受信任的 ZITADEL 实例
// 请勿在生产环境中使用
func WithInsecureSkipVerifyTLS() Option {
	return func(z *Zitadel) {
		z.insecureSkipVerifyTLS = true
	}
}

// WithPort 允许连接到运行在其他端口上的 ZITADEL 实例
func WithPort(port uint16) Option {
	return func(z *Zitadel) {
		z.port = strconv.Itoa(int(port))
	}
}

// WithTransportHeader 允许设置自定义请求头（例如 Proxy-Authorization），
// 这些请求头会同时随 HTTP（认证）和 gRPC（API）请求一起发送。
func WithTransportHeader(key, value string) Option {
	return func(z *Zitadel) {
		z.transportHeaders[key] = value
	}
}

// Origin 返回 HTTP Origin（schema://hostname[:port]），例如：
// https://your-instance.zitadel.cloud
// https://your-domain.com
// http://localhost:8080
func (z *Zitadel) Origin() string {
	return buildOrigin(z.domain, z.port, z.tls)
}

// Host 返回 domain:port（即使使用的是默认端口也会带上端口）
func (z *Zitadel) Host() string {
	return z.domain + ":" + z.port
}

func (z *Zitadel) IsTLS() bool {
	return z.tls
}

func (z *Zitadel) IsInsecureSkipVerifyTLS() bool {
	return z.insecureSkipVerifyTLS
}

func (z *Zitadel) Domain() string {
	return z.domain
}

func (z *Zitadel) TransportHeaders() map[string]string {
	return z.transportHeaders
}

func buildOrigin(hostname string, externalPort string, tls bool) string {
	if externalPort == "" || (externalPort == "443" && tls) || (externalPort == "80" && !tls) {
		return buildOriginFromHost(hostname, tls)
	}
	return buildOriginFromHost(fmt.Sprintf("%s:%s", hostname, externalPort), tls)
}

func buildOriginFromHost(host string, tls bool) string {
	schema := "https"
	if !tls {
		schema = "http"
	}
	return fmt.Sprintf("%s://%s", schema, host)
}
