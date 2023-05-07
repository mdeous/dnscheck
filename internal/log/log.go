package log

import (
	"fmt"
	"github.com/fatih/color"
	logging "log"
)

var (
	Red     = color.New(color.FgRed).SprintfFunc()
	RedBold = color.New(color.FgRed).Add(color.Bold).SprintfFunc()
	Green   = color.New(color.FgGreen).SprintfFunc()
	Blue    = color.New(color.FgBlue).SprintfFunc()
)

func Debug(format string, values ...interface{}) {
	msg := fmt.Sprintf(format, values...)
	logging.Println("- DEBUG - " + Green(msg))
}

func Info(format string, values ...interface{}) {
	msg := fmt.Sprintf(format, values...)
	logging.Println("- INFO - " + Blue(msg))
}

func Warn(format string, values ...interface{}) {
	msg := fmt.Sprintf(format, values...)
	logging.Println("- WARNING - " + Red(msg))
}

func Fatal(format string, values ...interface{}) {
	msg := fmt.Sprintf(format, values...)
	logging.Fatalln("- FATAL - " + Red(msg))
}

func Finding(format string, values ...interface{}) {
	msg := fmt.Sprintf(format, values...)
	logging.Println("- VULNERABLE DOMAIN - " + RedBold(msg))
}
