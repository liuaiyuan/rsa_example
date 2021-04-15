package def

import (
	"encoding/base64"
	"net/url"
	"rsa_example/pkg/utils"
	"rsa_example/pkg/utils/rsautil"
	"time"

	"github.com/google/go-querystring/query"
)

type (
	Login struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	Request struct {
		Timestamp  int64  `json:"timestamp"`
		Data       string `json:"data"`
		EncryptKey string `url:"encryptKey" json:"encrypt_key"` // 加密后的Key
		EncryptIV  string `url:"encryptIV" json:"encrypt_iv"`   // 加密后的IV
		Sign       string `url:"-" json:"sign"`
	}

	TokenInfo struct {
		Token   string `json:"token"`
		Expired int64  `json:"expired"`
	}
)

func GenLoginData() Login {
	return Login{
		Username: "admin",
		Password: "123456",
	}
}

func GenTokenInfo() TokenInfo {
	return TokenInfo{
		Token:   utils.RandString(32),
		Expired: time.Now().Add(time.Hour * 2).Unix(),
	}
}

func GenerateContent(request interface{}) string {
	v, _ := query.Values(request)

	value, _ := url.QueryUnescape(v.Encode())
	return value
}

func PublicVerifySign(key string, sign string, data []byte) error {
	publicKey, err := rsautil.PublicKeyFrom64(key)
	if err != nil {
		return err
	}
	if value, err := base64.StdEncoding.DecodeString(sign); err != nil {
		return err
	} else {
		return rsautil.PublicVerify(publicKey, value, data)
	}
}
