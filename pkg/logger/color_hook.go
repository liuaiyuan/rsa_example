package logger

import (
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
)

// ColorHook 日志颜色
type ColorHook struct {
	withColor map[log.Level]*color.Color
}

// Levels 等级
func (h *ColorHook) Levels() []log.Level {
	return log.AllLevels
}

// Fire 执行
func (h *ColorHook) Fire(e *log.Entry) error {
	if c, ok := h.withColor[e.Level]; ok {
		e.Message = c.Sprintf(e.Message)
	}

	return nil
}

// NewColorHook 创建
func NewColorHook() *ColorHook {
	var colors = map[log.Level]*color.Color{
		log.PanicLevel: color.New(color.FgRed),
		log.FatalLevel: color.New(color.FgHiRed),
		log.ErrorLevel: color.New(color.FgRed),
		log.WarnLevel:  color.New(color.FgHiYellow),
		log.InfoLevel:  color.New(color.FgCyan),
		log.DebugLevel: color.New(color.FgHiMagenta),
		log.TraceLevel: color.New(color.FgHiWhite),
	}

	return &ColorHook{withColor: colors}
}
