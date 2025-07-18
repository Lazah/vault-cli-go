package internal

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/Lazah/vault-cli-go/internal/vault"
	"github.com/spf13/viper"
)

func MoveSecrets(inputParams *CopyParams) {
	logger := slog.Default()
	var cfg ClientConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		logger.Error("failed to parse config", slog.String("error", err.Error()))
		os.Exit(10)
	}
	if cfg.SrcVault == nil {
		logger.Error("can't perform operation as vault client config is missing")
		os.Exit(10)
	}
	srcVaultClient, err := initVaultClient(cfg.SrcVault)
	if err != nil {
		logger.Error("failed to initialize vault client", slog.String("error", err.Error()))
		os.Exit(10)
	}
	srcVault, err := srcVaultClient.NewKv2Vault(inputParams.SrcMountPath)
	if err != nil {
		logger.Error("failed to initialize kv store", slog.String("path", inputParams.SrcMountPath))
		os.Exit(10)
	}
	logger.Info("initializing destination vault client")
	var dstVaultClient *vault.VaultClient
	if cfg.DstVault == nil {
		dstVaultClient, err = initVaultClient(cfg.SrcVault)
	} else {
		dstVaultClient, err = initVaultClient(cfg.DstVault)
	}
	if err != nil {
		logger.Error("failed to initialize vault client", slog.String("error", err.Error()))
		os.Exit(10)
	}
	dstVault, err := dstVaultClient.NewKv2Vault(inputParams.DstMountPath)
	if err != nil {
		logger.Error("failed to initialize destination vault", slog.String("error", err.Error()))
		os.Exit(10)
	}
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	srcPathChan := srcVault.GetSecretPaths(srcPath)
	sourcePaths := make([]string, 0)
	for path := range srcPathChan {
		sourcePaths = append(sourcePaths, path)
	}
	if len(sourcePaths) == 0 {
		logger.Info("nothing to move from path", slog.String("path", srcPath))
		os.Exit(0)
	}
	secretPathChan, metadataChan := startMetadataReaders(srcVault, inputParams.Versions)
	go sendDataToChan(sourcePaths, secretPathChan)
	secretVersions, err := collectResults(metadataChan)
	if err != nil {
		logger.Error(
			"an error occured while collecting metadata",
			slog.String("error", err.Error()),
		)
		os.Exit(10)
	}
	copyChan, failureChan, copierGroup := startSecretCopiers(srcVault, dstVault)
	dstPath := strings.Trim(inputParams.DstPath, "/")
	for _, secretVersion := range secretVersions {
		trimmedPath := strings.TrimPrefix(secretVersion.secretPath, srcPath)
		versionInfo := &SecretVersionsToCopy{
			origPath: secretVersion.secretPath,
			versions: secretVersion.versions,
			newPath:  fmt.Sprintf("%s%s", dstPath, trimmedPath),
		}
		copyChan <- versionInfo
	}
	close(copyChan)
	deleteSecrets := true
	failedPaths, err := collectResults(failureChan)
	if err != nil {
		logger.Error(
			"an error occured while collecting copy failures",
			slog.String("error", err.Error()),
		)
		deleteSecrets = false
	}
	copierGroup.Wait()
	if deleteSecrets {
		var removePaths []string
		removePaths = append(removePaths, sourcePaths...)
		for _, failedPath := range failedPaths {
			logger.Info("removing path from delete list", slog.String("path", failedPath))
			removePaths = slices.DeleteFunc(removePaths, func(path string) bool {
				return path == failedPath
			})
		}
		logger.Info("starting secret deletion")
		pathChan, deleteGroup := startDeleteWorkers(srcVault)
		for _, path := range removePaths {
			pathChan <- path
		}
		close(pathChan)
		deleteGroup.Wait()
	}
	err = srcVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for source vault")
	}
	err = dstVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for destination vault")
	}

}
