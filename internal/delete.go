package internal

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sync"

	"github.com/Lazah/vault-cli-go/internal/vault"
	"github.com/spf13/viper"
)

type DeleteParams struct {
	SrcMountPath string
	SrcPath      string
}

func DeleteSecrets(inputParams DeleteParams) {
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
	srcClient, err := initVaultClient(cfg.SrcVault)
	if err != nil {
		logger.Error("failed to initialize vault client", slog.String("error", err.Error()))
		os.Exit(10)
	}
	srcVault, err := srcClient.NewKv2Vault(inputParams.SrcMountPath)
	if err != nil {
		logger.Error("failed to initialize vault", slog.String("path", inputParams.SrcMountPath))
		os.Exit(10)
	}
	srcPathChan := srcVault.GetSecretPaths(inputParams.SrcPath)
	sourcePaths := make([]string, 0)
	for path := range srcPathChan {
		sourcePaths = append(sourcePaths, path)
	}
	pathChan, deleteGroup := startDeleteWorkers(srcVault)
	for _, path := range sourcePaths {
		pathChan <- path
	}
	close(pathChan)
	deleteGroup.Wait()
	err = srcClient.RevokeToken()
	if err != nil {
		logger.Error("failed to revoke session token")
	}
}

func initVaultClient(vaultCfg *VaultInstance) (*vault.VaultClient, error) {
	vaultUrl, err := url.Parse(vaultCfg.BaseURL)
	if err != nil {
		msg := fmt.Errorf("can't initialize vault client with given url: %w", err)
		return nil, msg
	}
	vaultClient, err := vault.NewClient(vaultUrl.String())
	if err != nil {
		msg := fmt.Errorf("vault client init failed: %w", err)
		return nil, msg
	}
	err = vaultClient.WithUserAuth(vaultCfg.UserCreds.Username, vaultCfg.UserCreds.Password, "")
	if err != nil {
		msg := fmt.Errorf("vault authentication failed: %w", err)
		return nil, msg
	}
	err = vaultClient.Authenticate()
	if err != nil {
		msg := fmt.Errorf("an error occured while performing authentication to vault: %w", err)
		return nil, msg
	}
	return vaultClient, nil
}

func startDeleteWorkers(srcVault *vault.Kv2Vault) (chan string, *sync.WaitGroup) {
	deleteGroup := new(sync.WaitGroup)
	deleteGroup.Add(2)
	pathChan := make(chan string, 100)
	for range 2 {
		go deleteSecrets(srcVault, pathChan, deleteGroup)
	}
	return pathChan, deleteGroup
}

func deleteSecrets(srcVault *vault.Kv2Vault, pathChan chan string, deleteGroup *sync.WaitGroup) {
	logger := slog.Default()
	defer deleteGroup.Done()
	for path := range pathChan {
		logger.Info("deleting secret", slog.String("path", path))
		err := srcVault.DeletSecret(path)
		if err != nil {
			logger.Error("failed to delete secret", slog.String("path", path))
		}
	}
}
