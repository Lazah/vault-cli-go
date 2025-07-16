package internal

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Lazah/vault-cli-go/internal/vault"
	"github.com/spf13/viper"
)

type CopyParams struct {
	SrcPath      string
	DstPath      string
	SrcMountPath string
	DstMountPath string
	Versions     int
}

func CopySecrets(inputParams CopyParams) {
	logger := slog.Default()
	logger.Info("initializing vault clients")
	srcVaultClient, dstVaultClient, err := initCopyVaultClients()
	if err != nil {
		logger.Error("failed to initialize clients for key copy", slog.String("error", err.Error()))
	}
	logger.Info("initializing source vault")
	srcVault, err := srcVaultClient.NewKv2Vault(inputParams.SrcMountPath)
	if err != nil {
		logger.Error("failed to initialize source vault", slog.String("error", err.Error()))
	}
	dstVault, err := dstVaultClient.NewKv2Vault(inputParams.DstMountPath)
	if err != nil {
		logger.Error("failed to initialize destination vault", slog.String("error", err.Error()))
	}
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	srcPathChan := srcVault.GetSecretPaths(srcPath)
	sourcePaths := make([]string, 0)
	for path := range srcPathChan {
		sourcePaths = append(sourcePaths, path)
	}
	pathVersions := getMetadataForPaths(sourcePaths, inputParams.Versions, *srcVault)
	versionChan, copierGroup := startSecretCopiers(srcVault, dstVault)
	dstPath := strings.Trim(inputParams.DstPath, "/")
	for path, versions := range pathVersions {
		trimmedPath := strings.TrimPrefix(path, srcPath)
		versionInfo := &SecretVersionsToCopy{
			origPath: path,
			versions: versions,
			newPath:  fmt.Sprintf("%s%s", dstPath, trimmedPath),
		}
		versionChan <- versionInfo
	}
	close(versionChan)
	copierGroup.Wait()
	err = srcVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for source vault")
	}
	err = dstVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for destination vault")
	}
}

func initCopyVaultClients() (*vault.VaultClient, *vault.VaultClient, error) {
	var cfg ClientConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		msg := fmt.Errorf("couldn't unmarshal config: %w", err)
		return nil, nil, msg
	}
	if cfg.SrcVault == nil {
		msg := fmt.Errorf("source vault config was empty")
		return nil, nil, msg
	}

	srcClient, err := performVaultAuth(cfg.SrcVault)
	if err != nil {
		msg := fmt.Errorf("failed to initialize source vault client: %w", err)
		return nil, nil, msg
	}
	var dstClient *vault.VaultClient
	if cfg.DstVault == nil {
		dstClient, err = performVaultAuth(cfg.SrcVault)
	} else {
		dstClient, err = performVaultAuth(cfg.DstVault)
	}
	if err != nil {
		msg := fmt.Errorf("failed to initialize destination vault client: %w", err)
		return nil, nil, msg
	}

	return srcClient, dstClient, nil
}

func performVaultAuth(vaultConfig *VaultInstance) (*vault.VaultClient, error) {
	switch vaultConfig.AuthType {
	case "ldap":
		vaultClient, err := vault.NewClient(vaultConfig.BaseURL)
		if err != nil {
			msg := fmt.Errorf(
				"couldn't initialize vault client with base url %q: %w",
				vaultConfig.BaseURL,
				err,
			)
			return nil, msg
		}
		err = vaultClient.WithLdapAuth(
			vaultConfig.UserCreds.Username,
			vaultConfig.UserCreds.Password,
			"",
		)
		if err != nil {
			msg := fmt.Errorf("couldn't set ldap as auth method for vault %w", err)
			return nil, msg
		}
		if vaultConfig.Insecure {
			err = vaultClient.Insecure()
		}
		if err != nil {
			msg := fmt.Errorf("an error occured while setting connection to insecure: %w", err)
			return nil, msg
		}
		err = vaultClient.Authenticate()
		if err != nil {
			msg := fmt.Errorf("authentication to vault failed: %w", err)
			return nil, msg
		}
		return vaultClient, nil
	case "token":
		vaultClient, err := vault.NewClient(vaultConfig.BaseURL)
		if err != nil {
			msg := fmt.Errorf(
				"couldn't initialize vault client with base url %q: %w",
				vaultConfig.BaseURL,
				err,
			)
			return nil, msg
		}
		err = vaultClient.WithTokenAuth(vaultConfig.TokenCreds.Token)
		if err != nil {
			msg := fmt.Errorf("failed to set token auth for vault client: %w", err)
			return nil, msg
		}
		return vaultClient, nil

	case "userpass":
		vaultClient, err := vault.NewClient(vaultConfig.BaseURL)
		if err != nil {
			msg := fmt.Errorf(
				"couldn't initialize vault client with base url %q: %w",
				vaultConfig.BaseURL,
				err,
			)
			return nil, msg
		}
		err = vaultClient.WithUserAuth(
			vaultConfig.UserCreds.Username,
			vaultConfig.UserCreds.Password,
			"",
		)
		if err != nil {
			msg := fmt.Errorf("failed to configure userpass auth to client: %w", err)
			return nil, msg
		}
		err = vaultClient.Authenticate()
		if err != nil {
			msg := fmt.Errorf("failed to perform userpass auth to vault: %w", err)
			return nil, msg
		}
		return vaultClient, nil
	}
	err := fmt.Errorf("unsupported auth type defined for vault: %q", vaultConfig.AuthType)
	return nil, err
}

func getMetadataForPaths(
	sourcePaths []string,
	versionCount int,
	srcVault vault.Kv2Vault,
) map[string][]int {
	logger := slog.Default()
	retVal := make(map[string][]int, 0)
	for _, path := range sourcePaths {
		metadata, err := srcVault.GetSecretMetadata(path)
		if err != nil {
			logger.Error(
				"failed to get metadata",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
			continue
		}
		if versionCount == 1 {
			retVal[path] = []int{metadata.Data.CurrentVersion}
		} else {
			versions := getSecretVersionsToCopy(*metadata, versionCount)
			retVal[path] = versions
		}

	}
	return retVal
}

func getSecretVersionsToCopy(secretMetadata vault.Kv2MetadataResp, keep int) []int {
	validVersions := filterDeletedSecretVersions(secretMetadata.Data.Versions)
	slices.Sort(validVersions)
	slices.Reverse(validVersions)
	if len(validVersions) > keep {
		validVersions = validVersions[:keep]
	}
	slices.Reverse(validVersions)
	return validVersions
}

func filterDeletedSecretVersions(versions map[string]vault.SecretVersion) []int {
	logger := slog.Default()
	retVal := make([]int, 0)
	for versionNumber, version := range versions {
		if version.Destroyed {
			continue
		}
		number, err := strconv.Atoi(versionNumber)
		if err != nil {
			logger.Error(
				"failed to convert version number to int",
				slog.String("number", versionNumber),
			)
			continue
		}
		retVal = append(retVal, number)
	}
	return retVal
}

type SecretVersionsToCopy struct {
	origPath string
	newPath  string
	versions []int
}

func startSecretCopiers(
	srcVault, dstVault *vault.Kv2Vault,
) (chan *SecretVersionsToCopy, *sync.WaitGroup) {
	versionChan := make(chan *SecretVersionsToCopy, 50)
	copierGroup := new(sync.WaitGroup)
	copierGroup.Add(2)
	for range 2 {
		go copySecrets(versionChan, copierGroup, srcVault, dstVault)
	}
	return versionChan, copierGroup
}

func copySecrets(
	secretChan chan *SecretVersionsToCopy,
	copierGroup *sync.WaitGroup,
	srcVault, dstVault *vault.Kv2Vault,
) {
	logger := slog.Default()
	defer copierGroup.Done()
	for secretInfo := range secretChan {
		logger.Info(
			"reading secret versions to copy",
			slog.String("vault", srcVault.DataUrl.Host),
			slog.String("path", secretInfo.origPath),
		)
		secrets := getSecretVersions(srcVault, secretInfo)
		logger.Info(
			"writing secrets to destination",
			slog.String("vault", dstVault.DataUrl.Host),
			slog.String("path", secretInfo.newPath),
		)
		writeSecretVersions(dstVault, secrets, secretInfo.newPath)
	}
}

func getSecretVersions(
	srcVault *vault.Kv2Vault,
	versionInfo *SecretVersionsToCopy,
) []*vault.Kv2SecretResp {
	logger := slog.Default()
	secretData := make([]*vault.Kv2SecretResp, 0)
	for _, versionNum := range versionInfo.versions {
		secret, err := srcVault.GetSecretVersion(versionInfo.origPath, versionNum)
		if err != nil {
			logger.Error(
				"failed to get data for secret version",
				slog.String("path", versionInfo.origPath),
				slog.Int("version", versionNum),
				slog.String("error", err.Error()),
			)
			continue
		}
		secretData = append(secretData, secret)
	}
	return secretData
}

func writeSecretVersions(dstVault *vault.Kv2Vault, secrets []*vault.Kv2SecretResp, path string) {
	logger := slog.Default()
	for _, secretResp := range secrets {
		data := secretResp.Data.Data
		err := dstVault.WriteSecret(path, data)
		if err != nil {
			logger.Error(
				"failed to write secret to path",
				slog.String("path", path),
				slog.String("vault", dstVault.DataUrl.Host),
			)
		}
	}
}
