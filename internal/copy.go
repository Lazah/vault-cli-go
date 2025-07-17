package internal

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

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
	}
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	srcPathChan := srcVault.GetSecretPaths(srcPath)
	sourcePaths := make([]string, 0)
	for path := range srcPathChan {
		sourcePaths = append(sourcePaths, path)
	}
	if len(sourcePaths) == 0 {
		logger.Info("nothing to copy from path", slog.String("path", srcPath))
		os.Exit(0)
	}
	secretPathChan, metadataChan := startMetadataReaders(srcVault, inputParams.Versions)
	go sendDataToChan(sourcePaths, secretPathChan)
	secretVersions, err := collectPointerResults(metadataChan)
	if err != nil {
		logger.Error(
			"an error occured while collecting metadata",
			slog.String("error", err.Error()),
		)
		os.Exit(10)
	}
	versionChan, errorChan, copierGroup := startSecretCopiers(srcVault, dstVault)
	dstPath := strings.Trim(inputParams.DstPath, "/")
	for _, secretVersion := range secretVersions {
		trimmedPath := strings.TrimPrefix(secretVersion.secretPath, srcPath)
		versionInfo := &SecretVersionsToCopy{
			origPath: secretVersion.secretPath,
			versions: secretVersion.versions,
			newPath:  fmt.Sprintf("%s%s", dstPath, trimmedPath),
		}
		versionChan <- versionInfo
	}
	close(versionChan)
	failedPaths, err := collectResults(errorChan)
	skipFailurePrint := false
	if err != nil {
		logger.Error("failed to collect copy failures")
		skipFailurePrint = true
	}
	copierGroup.Wait()
	err = srcVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for source vault")
	}
	err = dstVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for destination vault")
	}
	if !skipFailurePrint {
		fmt.Println("failed to copy following paths:")
		for _, path := range failedPaths {
			fmt.Println(path)
		}
	}
}

func startMetadataReaders(
	srcVault *vault.Kv2Vault,
	verCount int,
) (chan string, chan *SecretVersions) {
	pathChan := make(chan string, 50)
	metadataChan := make(chan *SecretVersions, 50)
	metaReaderGroup := new(sync.WaitGroup)
	metaReaderGroup.Add(2)
	for range 2 {
		go getMetadataForPaths(pathChan, metadataChan, metaReaderGroup, srcVault, verCount)
	}
	go closeMetadataResultChan(metadataChan, metaReaderGroup)
	return pathChan, metadataChan
}

type SecretVersions struct {
	secretPath string
	versions   []int
}

func getMetadataForPaths(
	pathChan chan string,
	metadataChan chan *SecretVersions,
	readerGroup *sync.WaitGroup,
	srcVault *vault.Kv2Vault,
	verCount int,
) {
	logger := slog.Default()
	ctx, cancel := context.WithTimeout(context.TODO(), 60*time.Second)
	defer readerGroup.Done()
metadataLookup:
	for {
		select {
		case <-ctx.Done():
			logger.Error("metadata processor context timeout")
			cancel()
			break metadataLookup
		case path, ok := <-pathChan:
			if !ok {
				logger.Debug("terminating metadata processor since input channel is closed")
				cancel()
				break metadataLookup
			}
			logger.Info("getting metadata from path", slog.String("path", path))
			metadata, err := srcVault.GetSecretMetadata(path)
			if err != nil {
				logger.Error(
					"an error occured while reading metadata from path",
					slog.String("path", path),
					slog.String("error", err.Error()),
				)
				continue
			}
			retVal := new(SecretVersions)
			retVal.secretPath = path
			if verCount == 1 {
				retVal.versions = []int{metadata.Data.CurrentVersion}
			} else {
				versions := getSecretVersionsToCopy(*metadata, verCount)
				retVal.versions = versions
			}
			metadataChan <- retVal
		}
	}
}

func closeMetadataResultChan(
	metadataChan chan *SecretVersions,
	readerGroup *sync.WaitGroup,
) {
	defer close(metadataChan)
	readerGroup.Wait()
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
) (chan *SecretVersionsToCopy, chan string, *sync.WaitGroup) {
	versionChan := make(chan *SecretVersionsToCopy, 50)
	errorChan := make(chan string, 50)
	copierGroup := new(sync.WaitGroup)
	copierGroup.Add(2)
	for range 2 {
		go copySecrets(versionChan, errorChan, copierGroup, srcVault, dstVault)
	}
	go closeCopyChans(errorChan, copierGroup)
	return versionChan, errorChan, copierGroup
}

func closeCopyChans(errorChan chan string, copyGroup *sync.WaitGroup) {
	defer close(errorChan)
	copyGroup.Wait()
}

func copySecrets(
	secretChan chan *SecretVersionsToCopy,
	errorChan chan string,
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
		failed := writeSecretVersions(dstVault, secrets, secretInfo.newPath)
		if failed {
			errorChan <- secretInfo.origPath
		}
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

func writeSecretVersions(
	dstVault *vault.Kv2Vault,
	secrets []*vault.Kv2SecretResp,
	path string,
) bool {
	logger := slog.Default()
	errorOccured := false
	for _, secretResp := range secrets {
		data := secretResp.Data.Data
		err := dstVault.WriteSecret(path, data)
		if err != nil {
			logger.Error(
				"failed to write secret to path",
				slog.String("path", path),
				slog.String("vault", dstVault.DataUrl.Host),
			)
			errorOccured = true
		}
	}
	return errorOccured
}

func collectPointerResults[T any](resChan chan *T) ([]*T, error) {
	ctx, ctxCancel := context.WithTimeout(context.TODO(), 60*time.Second)
	retVal := make([]*T, 0)
	for {
		select {
		case <-ctx.Done():
			ctxCancel()
			err := fmt.Errorf("collect context terminated with error: %w", ctx.Err())
			return nil, err
		case res, ok := <-resChan:
			if !ok {
				ctxCancel()
				return retVal, nil
			}
			retVal = append(retVal, res)
		}
	}

}

func collectResults[T any](resChan chan T) ([]T, error) {
	ctx, ctxCancel := context.WithTimeout(context.TODO(), 60*time.Second)
	retVal := make([]T, 0)
	for {
		select {
		case <-ctx.Done():
			ctxCancel()
			err := fmt.Errorf("collect context terminated with error: %w", ctx.Err())
			return nil, err
		case res, ok := <-resChan:
			if !ok {
				ctxCancel()
				return retVal, nil
			}
			retVal = append(retVal, res)
		}
	}

}

func sendDataToChan[T any](inputVals []T, targetChan chan T) {
	for _, val := range inputVals {
		targetChan <- val
	}
	close(targetChan)
}
