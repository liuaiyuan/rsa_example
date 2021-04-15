package aesutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

// Encrypt 加密
func Encrypt(data []byte, key, iv []byte) ([]byte, error) {
	aesBlockEncryptor, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	content := PKCS5Padding(data, aesBlockEncryptor.BlockSize())

	encrypted := make([]byte, len(content))

	aesEncryptor := cipher.NewCBCEncrypter(aesBlockEncryptor, iv)

	aesEncryptor.CryptBlocks(encrypted, content)

	return encrypted, nil
}

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipherText, padText...)
}

// Decrypt 解密
func Decrypt(src string, key, iv []byte) ([]byte, error) {

	data, err := hex.DecodeString(src)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(data))

	mode.CryptBlocks(plaintext, data)

	plaintext = PKCS5Trimming(plaintext)

	return plaintext, nil
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]

	return encrypt[:len(encrypt)-int(padding)]
}

