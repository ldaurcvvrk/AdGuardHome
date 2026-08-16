package permcheck

import (
	"context"
	"log/slog"
)

// NeedsMigration checks if migration is needed.
func NeedsMigration(ctx context.Context, l *slog.Logger, workDir, confPath string) bool {
	return false
}

// Migrate performs migration.
func Migrate(ctx context.Context, l *slog.Logger, workDir, dataDirPath, statsDir, querylogDir, confPath string) error {
	return nil
}

// Check checks permissions.
func Check(ctx context.Context, l *slog.Logger, workDir, dataDirPath, statsDir, querylogDir, confPath string) error {
	return nil
}
