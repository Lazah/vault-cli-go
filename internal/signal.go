package internal

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func CreateMainCtx() context.Context {
	logger := slog.Default()
	logger.Info("creating main context")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancelFunc := context.WithTimeout(context.TODO(), 4*time.Hour)
	go func() {
		<-sigs
		logger.Info("canceling main context due to signal")
		cancelFunc()
	}()
	return ctx
}
