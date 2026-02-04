package logger

import (
	"log"
	"os"
	"strings"
)

type LogLevel int

const (
	LevelTrace LogLevel = iota
	LevelDebug
	LevelInfo
	LevelError
	LevelFatal
)

var currentLevel = LevelInfo

var levelTags = map[LogLevel]string{
	LevelTrace: "TRACE",
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelError: "ERROR",
	LevelFatal: "FATAL",
}

// SetLevel controls the logs verbosity (default is LevelInfo).
func SetLevel(level string) {
	switch strings.ToLower(level) {
	case "trace":
		currentLevel = LevelTrace
	case "debug":
		currentLevel = LevelDebug
	case "error":
		currentLevel = LevelError
	case "fatal":
		currentLevel = LevelFatal
	default:
		currentLevel = LevelInfo
	}
	Debug("Current log level is set to %s", levelTags[currentLevel])
}

func logMsg(level LogLevel, msg string, args ...any) {
	if level < currentLevel {
		return
	}

	tag := levelTags[level]

	if level == LevelFatal {
		log.Fatalf(tag+" "+msg, args...)
		os.Exit(1)
	}

	log.Printf("["+tag+"] "+msg, args...)
}

// Trace logs at LevelTrace.
func Trace(msg string, args ...any) { logMsg(LevelTrace, msg, args...) }

// Debug logs at LevelDebug.
func Debug(msg string, args ...any) { logMsg(LevelDebug, msg, args...) }

// Info logs at LevelInfo.
func Info(msg string, args ...any) { logMsg(LevelInfo, msg, args...) }

// Error logs at LevelError.
func Error(msg string, args ...any) { logMsg(LevelError, msg, args...) }

// Fatal logs at LevelFatal.
func Fatal(msg string, args ...any) { logMsg(LevelFatal, msg, args...) }
