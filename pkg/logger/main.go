package logger

import (
	log "github.com/sirupsen/logrus"
)

// InitLogger 初始化日志
func InitLogger() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp:       false,
		FullTimestamp:          true,
		TimestampFormat:        "2006/01/02 15:04:05",
		DisableLevelTruncation: true,
		PadLevelText:           true,
	})
	log.AddHook(NewColorHook())
}
