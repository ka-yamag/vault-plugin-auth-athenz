package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger = createLogger(
		zap.LevelEnablerFunc(errLevelEnabler),
		zap.LevelEnablerFunc(outLevelEnabler),
	)
)

func errLevelEnabler(level zapcore.Level) bool {
	return level >= zapcore.ErrorLevel
}

func outLevelEnabler(level zapcore.Level) bool {
	return level < zapcore.ErrorLevel
}

// createLogger build zap logger
func createLogger(errLevelFunc, outLevelFunc zap.LevelEnablerFunc) *zap.Logger {
	consoleDebugging := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)
	consoleEncoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())

	logfile, _ := os.OpenFile("/tmp/test.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, errLevelFunc),
		zapcore.NewCore(consoleEncoder, consoleDebugging, outLevelFunc),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(logfile), outLevelFunc),
	)
	return zap.New(core, zap.AddStacktrace(zap.ErrorLevel), zap.AddCaller())
}

// GetLogger is used to get logger used in globally in each components
func GetLogger() *zap.Logger {
	return logger
}
