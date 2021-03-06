package main

import (
	log "github.com/sirupsen/logrus"
	"os"
	"rsa_example/pkg/logger"
	"rsa_example/pkg/utils/rsautil"
)

func main() {
	logger.InitLogger()
	log.SetLevel(log.TraceLevel)

	privateKey, publicKey, err := rsautil.GenerateKey64()
	if err != nil {
		log.Errorf("获取证书失败: %s", err.Error())
		return
	}
	writeToFile("pri.txt", privateKey)
	writeToFile("pub.txt", publicKey)

}

func writeToFile(filename string, value string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Errorf("打开文件失败:%s", err.Error())
		return
	}

	defer file.Close()

	file.WriteString(value)
}
