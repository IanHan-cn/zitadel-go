package authentication

import (
	"encoding/json"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

// State 表示认证流程开始前用户应用的状态，
// 用于在应用与登录界面之间来回传递状态，例如发起登录流程时。
type State struct {
	RequestedURI string
}

func (s *State) Encrypt(key string) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return crypto.EncryptAES(string(data), key)
}

func DecryptState(data, key string) (*State, error) {
	decrypted, err := crypto.DecryptAES(data, key)
	if err != nil {
		return nil, err
	}
	state := new(State)
	err = json.Unmarshal([]byte(decrypted), state)
	return state, err
}
