package internal

import (
	"log/slog"
	"os"

	"github.com/spf13/viper"
)

func SetupLogger() {
	lvlStr := viper.GetString("logLevel")
	logLevel := getLogLevel(lvlStr)
	loggerOptions := &slog.HandlerOptions{
		Level: logLevel,
	}
	handler := slog.NewTextHandler(os.Stderr, loggerOptions)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func getLogLevel(lvl string) slog.Level {
	switch lvl {
	case "err", "error":
		return slog.LevelError
	case "warn", "warning":
		return slog.LevelWarn
	case "info":
		return slog.LevelInfo
	case "debug":
		return slog.LevelDebug
	default:
		return slog.LevelError
	}
}
