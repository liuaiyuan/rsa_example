package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"rsa_example/def"
	"rsa_example/logger"
	"rsa_example/utils"
	"rsa_example/utils/aesutil"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	apiPublicKey     = "MIIBCgKCAQEAku9238NC/Mhe7o+uzLHffZcxTWQG8Bid0nnpOSyivQSPoas0DpL3McDlfZLFGbnyrSCm3KIwJjCgTTdmRaI96CwysLjMu4rfxinlqJ0EFmKt8gj/SIZMOH69DH+2Y2aRkvd14NeBYdWtceggm27+uM27HjOTejmynmFtRHlu93xbMiGpVelQVkc2XbN6Ik4U+RCrKH7L3iuxbNUvzCQxXQn3E88+b6CstbPh+R5yWdiHljqEJzFzLIFvvogejmTDUORjDkeYywoXCQ/48nSS/H5CCJGrRkXcqI9AR+eDQgsYNzS9srlgBSrc4YiyxJ3j0RuBHpaWCnSn7ic+sog+4wIDAQAB"
	clientPrivateKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDH48AzgHKcB50zqCNl6hb0HWMHso/qDKsc/dR8PlXaRTE3jHuPN6xFDu7PE71ZnNYbywGUUSELMy1X/8jW6xl9H9AJ+E5vMIIz0UW+ekR2Y+Py6m8qS3NbcCUG9M9C+Dzkxsh3SPfjZQ8QjNNB0EGbkmuTM3TdJRr6GiTE3/HJ5EOqmixWuPurNRYuHIvMer28dzn0WA6pzGyBKoxFTCDdVOf5YqruYQhi7ltdIPM/5rkuIG7Hc79hK+zdrkvTReR/s0uLZP/py4jlW+yJQw6imO+btio2v56E/8+U92mFFg8mX7dt3N8Wgt5PDFqtsMsW5aIk03qNehfE5BiNoXaPAgMBAAECggEBAKPZvB47ZzchQqoqZEHRPlmCkT+pDjEDi2wrYXcqvcM6vppTLKF8OFkvYXAbNTZ0yklkAfpq+lQs8jlVMXOCqZUYc7cIdHrOX5xMKgh2PxJw1VS0+MTJrljAt4lZOWAjDf9WNtMY3CHpIA0n8q/bHzyALHAwWNZB6TgkIAnFrHQZlFy/XnICpnZMcCwo8vUdRph4G5naY1QGecgXnTJ02UKG+IKiMspnEIqfndv2bX8ihTzCbn19Do9RTbvMavGWBiO6MYUng1khJYcdstYtrF36FQZ6yre8XejRZNISjw+KZGMTOitatmJV1JtsVH6+ex3iHlqQrV4UVlrQ7iSwWZECgYEAydgxHc0yPPw/Jjem67BeH/2eXf5OMbLT/G7+2/ReVpk4WiVWPaUC/k29NijZ/VO31PpGOl6WMIqz+NbUv6xUNIVN0sj6jVfCJSKBwlFpjJJ2S0DiFdVt9hhXcH73U/j/ga7lqohS11E+a3m5A8LNzKQQLpH6DuqhF2yBiqmEtacCgYEA/YVJ/sf3Z8EDKevFKxTt5Kj5uvh+JFG8u8VTyuqBuPr1Fkz2IeyequCJ6r1v7lfN1Ck3uBAKkQrXLeC1Ba7hhk0rS4Ur1UNG9bVodXa8VjCkeWqM3D8Wx16suBr+HFUmnfKnVtaGKrlqNt6an/0+NCDuLrwWrfO6DssIkLuoJNkCgYBEPL5+ILz3OR/wP6hCzeFEV22OwUaWLqrUEIJAwiCSjkIq16yMMpkMeCObh7wKlJ71dZcAbLHBv2KQobBTDGN7TgW9WQy7dAvCmiPcGcHhMDKlxk2oq/r808Xb1lCvJuLaaNJkEKpQ+Lptgz01NEp3AJAn7lnnaRME5D33LtAayQKBgQDuayhwfBw2rfTMutbdMjybezIIXOM8QsZMjEHGJg5DKXfONiiPNNju+GWbpfYa3uZKLU0iQ6u8RcahdZ6oLpQXWoFp716OnEuija0kMrriD7LOIJ9CDe7dJjMmnPP3Lzk291naN7tLeL3jxisCZQXXvlRhDTAC/aAvg0+V1XVG2QKBgQCsQCjI9XCTZ2spFA5dNUUwhdvEC0Nr11gKAr9UQUj99gMPtdKiv7KqydEteukDBAIBCrQyGdJ5r8WECV/8M8+nIjEVVcGWSRgGqdygIb20UvEtUDKjRI3EV9qnSfyYyKTlVyTcD8+BsDot6R/wHJkWRpiePzGTOqdIdCXxQd9lCg=="
)

func main() {
	logger.InitLogger()
	log.SetLevel(log.TraceLevel)

	var (
		data   = def.GenLoginData()
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

	rsaEncryptKey, err := utils.EncryptPublicKey(apiPublicKey, aesKey)
	if err != nil {
		log.Errorf("加密aesKey失败: %s", err.Error())
		return
	}

	rsaEncryptIv, err := utils.EncryptPublicKey(apiPublicKey, aesIv)
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
	sign, err := utils.SignByPrivateKey(clientPrivateKey, signature)

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

	resp, err := http.Post("http://127.0.0.1:8080/login", "application/json", bytes.NewReader(requestValue))
	if err != nil {
		log.Errorf("请求失败:%s", err.Error())
		return
	}

	defer resp.Body.Close()

	log.Infof("status: %s | status Code: %d", resp.Status, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("读取body失败: %s", err.Error())
		return
	}

	decode(body)
}

func decode(msg []byte) {
	var body def.Request
	if err := json.Unmarshal(msg, &body); err != nil {
		log.Errorf("读取json失败: %s", err.Error())
		return
	}

	log.Infof("业务加密数据:%v", body)

	signAgain := def.GenerateContent(body)

	// 签名验证
	if err := def.PublicVerifySign(apiPublicKey, body.Sign, []byte(signAgain)); err != nil {
		log.Errorf("签名验证失败: %s", err.Error())
		return
	}

	log.Debugf("签名验证成功")

	// 数据解密
	// 1 RSA解密AESKey和IV
	decryptKey, err := utils.DecryptPrivateKey(clientPrivateKey, body.EncryptKey)
	if err != nil {
		log.Errorf("解密aesKey失败: %s", err.Error())
		return
	}

	decryptIv, err := utils.DecryptPrivateKey(clientPrivateKey, body.EncryptIV)
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
}
