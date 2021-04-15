package main

import (
	"admin_api/pkg/logger"
	"admin_api/pkg/utils"
	aesutil "admin_api/pkg/utils/aes"
	"admin_api/test/def"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/kataras/iris/v12"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	apiPrivateKey   = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCS73bfw0L8yF7uj67Msd99lzFNZAbwGJ3Seek5LKK9BI+hqzQOkvcxwOV9ksUZufKtIKbcojAmMKBNN2ZFoj3oLDKwuMy7it/GKeWonQQWYq3yCP9Ihkw4fr0Mf7ZjZpGS93Xg14Fh1a1x6CCbbv64zbseM5N6ObKeYW1EeW73fFsyIalV6VBWRzZds3oiThT5EKsofsveK7Fs1S/MJDFdCfcTzz5voKy1s+H5HnJZ2IeWOoQnMXMsgW++iB6OZMNQ5GMOR5jLChcJD/jydJL8fkIIkatGRdyoj0BH54NCCxg3NL2yuWAFKtzhiLLEnePRG4EelpYKdKfuJz6yiD7jAgMBAAECggEAT5d/YP44Tw2Kvtb97Mt9MF6xyiYgy/XJp7V57AqNrK3Hz98ZN7vMQxsmNLtIIQNkvPsu59zDECzO6ITV1Wpo9lbarnesDvrO9FzFlmxXRnj1mGHfRr3Yk9GzPg4AEiABQwbgx4Z1AzXn2gfPgeLCAAERFu8BN/gBFWHY+np87XmRHqRNDEhg9bfKbJqoBPUT9OdtYv5vjxe2PuJZIrdamGno0O0aGby89W/kDD8tUMnruykrShI5oandoFHSflRvyXSq9lXMm6qpaC4zPmkVlegOO0JNpbx3fkNx6KoWxY0SeuSMMX9r0qrhxUK9WtCBw8hczw8srO6MU6NHWzM7wQKBgQDBnF4gnKvCdEeZb5rpXQylaOfGskdVR1Gn624Lk5uknXorqZOGYHLFY9kg9Nnwz2eLb5GT145ehY+ThcC7TdH3D9arkeiRAL0u+Z7f30NVhXl7zkpWKqkmbqeLuiBv5MjpVbilsMJ3tTpf2j0EhbUc/LLBtI3SDNsUw/eOmUs7ywKBgQDCSK31z7q0O0wjUP93PtRlE/x0WjWZR2OILJ95y+Y6qCoqHyohaOy5H4OECYXi82oALnhutzVxVQdEtjOB8Tp1gNsIbqoQZ4LljyRJpUpOdkHAdq0mJdY/tgEWdATdqEkicuZWNjSnve9cOwo9vR80AZgUBV105Yx4WhnNPjpWSQKBgQC+XfizSjkcNucbt//yixpfHbofxbWb5Uclu7h1S4rTHkA85Dz4+KaA7X9WB0qvm88s6+ORIXaL+/lDTVVHFepoabti8VFiGf7qTGjpqQX09guQLzMqbEHrVwwIuFcijir6Ot4WlKlxuNEP5G7wnmOJf/JnwhdcPGXBkjo8jP/LZwKBgEOwMLOQkRrUAf3X7XltMXCZ2v3qo/voLFw4N8Omb2sGRdJxEyuas8b3nMl2y+e7KLYxepIQUJVQq3ycAiwGkHh50VYJwESA29EA4wKpjM7zUossjbzZt+Bwl8Zr23oidICFCY0Fy6iZevhmNXY3GtTyrTpkeCAPDbaspYqlYIvJAoGAJS8DObXjJx9TAOUGdsTfHS22qUVJDcSTLKB16kC9zBVmx7RKMi0+eVxHAZJAlXsaUoxAb8iX018i8vlmhF4/gmAkPC58FM7VkByGQ+YHT4dCPU71dMLfSt7f6yBw1y6xhoSo5CwDZNbSBEN1HIru6PWlJGgqsvq0pI0dlzwxyd8="
	clientPublicKey = "MIIBCgKCAQEAx+PAM4BynAedM6gjZeoW9B1jB7KP6gyrHP3UfD5V2kUxN4x7jzesRQ7uzxO9WZzWG8sBlFEhCzMtV//I1usZfR/QCfhObzCCM9FFvnpEdmPj8upvKktzW3AlBvTPQvg85MbId0j342UPEIzTQdBBm5JrkzN03SUa+hokxN/xyeRDqposVrj7qzUWLhyLzHq9vHc59FgOqcxsgSqMRUwg3VTn+WKq7mEIYu5bXSDzP+a5LiBux3O/YSvs3a5L00Xkf7NLi2T/6cuI5VvsiUMOopjvm7YqNr+ehP/PlPdphRYPJl+3bdzfFoLeTwxarbDLFuWiJNN6jXoXxOQYjaF2jwIDAQAB"
)

func main() {
	logger.InitLogger()
	log.SetLevel(log.TraceLevel)

	app := iris.Default()

	app.Post("/login", rsaMiddleware, handleLogin)

	if err := app.Run(iris.Addr(":8080")); err != nil {
		log.Errorf("服务器启动失败: %s", err.Error())
	}
}

func rsaMiddleware(ctx iris.Context) {
	fmt.Println(ctx.GetContentLength())

	var body def.Request

	if err := ctx.ReadJSON(&body); err != nil {
		log.Errorf("读取json失败: %s", err.Error())
		return
	}

	log.Infof("业务加密数据:%v", body)

	signAgain := def.GenerateContent(body)

	// 签名验证
	if err := def.PublicVerifySign(clientPublicKey, body.Sign, []byte(signAgain)); err != nil {
		log.Errorf("签名验证失败: %s", err.Error())
		return
	}

	log.Debugf("签名验证成功")

	// 数据解密
	// 1 RSA解密AESKey和IV
	decryptKey, err := utils.DecryptPrivateKey(apiPrivateKey, body.EncryptKey)
	if err != nil {
		log.Errorf("解密aesKey失败: %s", err.Error())
		return
	}

	decryptIv, err := utils.DecryptPrivateKey(apiPrivateKey, body.EncryptIV)
	if err != nil {
		log.Errorf("解密aesIv失败: %s", err.Error())
		return
	}

	log.Infof("解密后的AESKey: %s", decryptKey)
	log.Infof("解密后的AESIV: %s", decryptIv)

	// 2 解密业务数据
	decryptData, err := aesutil.Decrypt(body.Data, decryptKey, decryptIv)
	if err != nil {
		log.Errorf("解密业务数据失败: %s", err.Error())
		return
	}

	ctx.Request().Body = ioutil.NopCloser(bytes.NewBuffer(decryptData))
	ctx.Next()
}

func handleLogin(ctx iris.Context) {
	var login def.Login
	fmt.Println(ctx.ReadJSON(&login))
	fmt.Println(ctx.GetContentLength())
	fmt.Println(login.Username)
	fmt.Println(login.Password)

	response(ctx)
}

func handleLogin2(ctx iris.Context) {
	// 1. 解析body数据至结构体
	var body def.Request
	if err := ctx.ReadJSON(&body); err != nil {
		log.Errorf("读取json失败: %s", err.Error())
		return
	}

	log.Infof("业务加密数据:%v", body)

	signAgain := def.GenerateContent(body)

	// 签名验证
	if err := def.PublicVerifySign(clientPublicKey, body.Sign, []byte(signAgain)); err != nil {
		log.Errorf("签名验证失败: %s", err.Error())
		return
	}

	log.Debugf("签名验证成功")

	// 数据解密
	// 1 RSA解密AESKey和IV
	decryptKey, err := utils.DecryptPrivateKey(apiPrivateKey, body.EncryptKey)
	if err != nil {
		log.Errorf("解密aesKey失败: %s", err.Error())
		return
	}

	decryptIv, err := utils.DecryptPrivateKey(apiPrivateKey, body.EncryptIV)
	if err != nil {
		log.Errorf("解密aesIv失败: %s", err.Error())
		return
	}

	log.Infof("解密后的AESKey: %s", decryptKey)
	log.Infof("解密后的AESIV: %s", decryptIv)

	// 2 解密业务数据
	decryptData, err := aesutil.Decrypt(body.Data, decryptKey, decryptIv)
	if err != nil {
		log.Errorf("解密业务数据失败: %s", err.Error())
		return
	}

	fmt.Println(string(decryptData))

	//ioutil.ReadAll(ctx.Request().Body)
	//io.C

	response(ctx)
}

func response(ctx iris.Context) {
	var (
		data   = def.GenTokenInfo()
		aesKey = utils.RandString(16)
		aesIv  = utils.RandString(16)
	)

	log.Infof("原始AesKey: %s", aesKey)
	log.Infof("原始AesIv: %s", aesIv)

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Errorf("json编码失败: %s", err.Error())
		return
	}

	log.Infof("原始业务数据: %s", jsonData)
	encryptData, err := aesutil.Encrypt(jsonData, []byte(aesKey), []byte(aesIv))
	if err != nil {
		log.Errorf("业务数据加密失败:%s", err.Error())
		return
	}

	log.Infof("加密后的业务数据: %s", strings.ToUpper(hex.EncodeToString(encryptData)))

	rsaEncryptKey, err := utils.EncryptPublicKey(clientPublicKey, aesKey)
	if err != nil {
		log.Errorf("加密aesKey失败: %s", err.Error())
		return
	}

	rsaEncryptIv, err := utils.EncryptPublicKey(clientPublicKey, aesIv)
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
	sign, err := utils.SignByPrivateKey(apiPrivateKey, signature)
	if err != nil {
		log.Errorf("签名失败:%s", err.Error())
		return
	}
	request.Sign = sign

	ctx.StopWithJSON(http.StatusOK, request)
}
