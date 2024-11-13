package logger

import "log"

const (
	COLOR_RED    = "\033[31m"
	COLOR_YELLOW = "\033[33m"
	COLOR_BLUE   = "\033[36m"
	COLOR_RESET  = "\033[0m"
)

func Error(msg string) {
	log.Printf("%s[ERROR]%s %s\n", COLOR_RED, COLOR_RESET, msg)
}

func Info(msg string) {
	log.Printf("%s[INFO]%s %s\n", COLOR_BLUE, COLOR_RESET, msg)
}

func Warn(msg string) {
	log.Printf("%s[WARN]%s %s\n", COLOR_YELLOW, COLOR_RESET, msg)
}
