package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigFromKeyFileData(t *testing.T) {
	// 生成一个用于测试的 RSA 私钥示例
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate rsa key")
	// 并将其编码为 PEM 格式
	privateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)
	// 将换行符替换为 \n，以便嵌入 JSON 中
	privateKeySingleLine := strings.ReplaceAll(string(privateKey), "\n", "\\n")

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *KeyFile
		wantErr bool
	}{
		{
			name: "valid service account key",
			args: args{
				data: []byte(fmt.Sprintf(`{
					"type": "serviceaccount",
					"keyId": "key1",
					"key": "%s",
					"userId": "user1"
				}`, privateKeySingleLine)),
			},
			want: &KeyFile{
				Type:   ServiceAccountKey,
				KeyID:  "key1",
				Key:    privateKey,
				UserID: "user1",
			},
		},
		{
			name: "valid application key",
			args: args{
				data: []byte(fmt.Sprintf(`{
					"type": "application",
					"keyId": "key2",
					"key": "%s",
					"clientId": "client1",
					"appId": "app1"
				}`, privateKeySingleLine)),
			},
			want: &KeyFile{
				Type:     ApplicationKey,
				KeyID:    "key2",
				Key:      privateKey,
				ClientID: "client1",
				AppID:    "app1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConfigFromKeyFileData(tt.args.data)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)

			// 同时测试 JSON 序列化
			data, err := got.MarshalJSON()
			require.NoError(t, err)
			require.JSONEq(t, string(tt.args.data), string(data))
		})
	}
}
