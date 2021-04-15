package utils

import (
	"encoding/base64"
	"math/rand"
	"rsa_example/utils/rsautil"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@#$%^&**()+=!~")

func RandString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func EncryptPublicKey(key string, data string) (string, error) {
	publicKey, err := rsautil.PublicKeyFrom64(key)
	if err != nil {
		return "", err
	}

	if value, err := rsautil.PublicEncrypt(publicKey, []byte(data)); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(value), nil
	}
}

func DecryptPrivateKey(key string, data string) ([]byte, error) {
	privateKey, err := rsautil.PrivateKeyFrom64(key)
	if err != nil {
		return nil, err
	}
	enData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return rsautil.PrivateDecrypt(privateKey, enData)

}

func SignByPrivateKey(key string, data string) (string, error) {
	privateKey, err := rsautil.PrivateKeyFrom64(key)
	if err != nil {
		return "", err
	}

	if value, err := rsautil.PrivateSign(privateKey, []byte(data)); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(value), nil
	}
}
