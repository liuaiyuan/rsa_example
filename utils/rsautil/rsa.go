package rsautil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

const (
	rsaKeySize = 2048
)

// hash 获取哈希数据
func hash(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

// GenerateKey 生成私钥和公钥
func GenerateKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pri, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, err
	}
	return pri, &pri.PublicKey, nil
}

// GenerateKeyBytes 获取[]byte]格式的私钥和公钥
func GenerateKeyBytes() (privateBytes, publicBytes []byte, err error) {
	pri, pub, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	priBytes, err := x509.MarshalPKCS8PrivateKey(pri)
	if err != nil {
		return nil, nil, err
	}
	pubBytes := x509.MarshalPKCS1PublicKey(pub)
	return priBytes, pubBytes, nil
}

// GenerateKey64 获取base64格式的私钥和公钥
func GenerateKey64() (pri64, pub64 string, err error) {
	pri, pub, err := GenerateKeyBytes()
	if err != nil {
		return "", "", nil
	}
	return base64.StdEncoding.EncodeToString(pri), base64.StdEncoding.EncodeToString(pub), nil
}

// PublicKeyFrom 将[]byte格式的公钥解析成公钥
func PublicKeyFrom(key []byte) (*rsa.PublicKey, error) {
	if pub, err := x509.ParsePKCS1PublicKey(key); err != nil {
		return nil, err
	} else {
		return pub, nil
	}
}

// PublicKeyFrom64 将base64格式的公钥解析成公钥
func PublicKeyFrom64(key string) (*rsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return PublicKeyFrom(b)
}

// PrivateKeyFrom 将[]byte格式的私钥解析成私钥
func PrivateKeyFrom(key []byte) (*rsa.PrivateKey, error) {
	pri, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	p, ok := pri.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key")
	}
	return p, nil
}

// PrivateKeyFrom64 将base64格式的私钥解析成私钥
func PrivateKeyFrom64(key string) (*rsa.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFrom(b)
}

// PublicEncrypt 使用公钥解密数据
func PublicEncrypt(key *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, key, data)
}

// PublicSign 使用公钥签名
func PublicSign(key *rsa.PublicKey, data []byte) ([]byte, error) {
	return PublicEncrypt(key, hash(data))
}

// PublicVerify 使用公钥验证数据
func PublicVerify(key *rsa.PublicKey, sign, data []byte) error {
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash(data), sign)
}

// PrivateDecrypt 使用私钥加密数据
func PrivateDecrypt(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, key, data)
}

// PrivateSign 使用私钥签名
func PrivateSign(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash(data))
}

// PrivateVerify 使用私钥验证数据
func PrivateVerify(key *rsa.PrivateKey, sign, data []byte) error {
	h, err := PrivateDecrypt(key, sign)
	if err != nil {
		return err
	}
	if !bytes.Equal(h, hash(data)) {
		return rsa.ErrVerification
	}
	return nil
}
