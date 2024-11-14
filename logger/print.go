package logger

import "log"

const (
	COLOR_RED    = "\033[31m"
	COLOR_YELLOW = "\033[33m"
	COLOR_BLUE   = "\033[36m"
	COLOR_GREEN  = "\033[32m"
	COLOR_RESET  = "\033[0m"
)

func Error(function string, msg string) {
	log.Printf("%s[ERROR]%s [%s]%s %s\n", COLOR_RED, COLOR_BLUE, function, COLOR_RESET, msg)
}

func Info(function string, msg string) {
	log.Printf("%s[INFO]%s [%s]%s %s\n", COLOR_BLUE, COLOR_BLUE, function, COLOR_RESET, msg)
}

func Warn(function string, msg string) {
	log.Printf("%s[WARN]%s [%s]%s %s\n", COLOR_YELLOW, COLOR_BLUE, function, COLOR_RESET, msg)
}

func Test(function string, msg string) {
	log.Printf("%s[TEST]%s [%s]%s %s\n", COLOR_GREEN, COLOR_BLUE, function, COLOR_RESET, msg)
}
