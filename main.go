package main

import (
	"admin_api/pkg/logger"
	"admin_api/pkg/utils"
	"admin_api/pkg/utils/rsautil"
	"admin_api/test/def"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	aesutil "admin_api/pkg/utils/aes"
	log "github.com/sirupsen/logrus"
)

type User struct {
	Id       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}


func main() {
	logger.InitLogger()
	log.SetLevel(log.TraceLevel)

	privateKey, publicKey, err := rsautil.GenerateKey64()
	if err != nil {
		log.Errorf("获取证书失败: %s", err.Error())
		return
	}

	log.Debugf("公钥证书: %s", publicKey)
	log.Debugf("私钥证书: %s", privateKey)

	var aesKey = utils.RandString(16)
	var iv = utils.RandString(16)

	log.Infof("原始AESKey: %s", aesKey)
	log.Infof("原始IV: %s", iv)

	var data = genUserData()

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Errorf("json编码失败: %s", err.Error())
		return
	}

	log.Infof("原始业务数据: %s", jsonData)
	encryptData, _ := aesutil.Encrypt(jsonData, []byte(aesKey), []byte(iv))

	log.Infof("加密后的业务数据: %s", strings.ToUpper(hex.EncodeToString(encryptData)))

	rsaEncryptKey, err := utils.EncryptPublicKey(publicKey, aesKey)
	if err != nil {
		log.Errorf("加密aesKey失败: %s", err.Error())
		return
	}

	rsaEncryptIv, err := utils.EncryptPublicKey(publicKey, iv)
	if err != nil {
		log.Errorf("加密aesIv失败: %s", err.Error())
		return
	}

	log.Infof("加密后的AESKey：%s ", rsaEncryptKey)
	log.Infof("加密后的IV：%s ", rsaEncryptIv)

	var request = &def.Request{
		Timestamp:  time.Now().Unix(),
		EncryptKey: rsaEncryptKey,
		EncryptIV:  rsaEncryptIv,
		Data:       strings.ToUpper(hex.EncodeToString(encryptData)),
	}

	signature := def.GenerateContent(request)
	sign, err := utils.SignByPrivateKey(privateKey, signature)

	if err != nil {
		log.Errorf("签名失败:%s", err.Error())
		return
	}
	request.Sign = sign

	requestValue, err := json.Marshal(request)
	if err != nil {
		log.Errorf("json加密失败:%s", err.Error())
		return
	}

	log.Infof("最终接口参数:%s", requestValue)

	signAgain := def.GenerateContent(request)

	// 签名验证
	if err := def.PublicVerifySign(publicKey, sign, []byte(signAgain)); err != nil {
		log.Errorf("签名验证失败: %s", err.Error())
		return
	}

	// 数据解密
	// 1 RSA解密AESKey和IV
	decryptKey, err := utils.DecryptPrivateKey(privateKey, request.EncryptKey)
	if err != nil {
		log.Errorf("解密aesKey失败: %s", err.Error())
		return
	}

	decryptIv, err := utils.DecryptPrivateKey(privateKey, request.EncryptIV)
	if err != nil {
		log.Errorf("解密aesIv失败: %s", err.Error())
		return
	}

	log.Infof("解密后的AESKey: %s", decryptKey)
	log.Infof("解密后的AESIV: %s", decryptIv)

	// 2 解密业务数据
	decryptData, err := aesutil.Decrypt(request.Data, decryptKey, decryptIv)
	if err != nil {
		log.Errorf("解密业务数据失败: %s", err.Error())
		return
	}

	fmt.Println(string(decryptData))
}

func genUserData() User {
	return User{
		Id:       10000,
		Username: "admin",
		Password: "123456",
	}
}



