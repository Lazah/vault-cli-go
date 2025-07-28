package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lazah/vault-cli-go/internal/vault"
	"github.com/spf13/viper"
)

//from copy file

type KvParams struct {
	SrcPath      string
	DstPath      string
	SrcMountPath string
	DstMountPath string
	Versions     int
	FilterPaths  bool
	FilterExpStr string
	ModDstPaths  bool
	OldPathPart  string
	NewPathPart  string
}

func CopySecrets(inputParams KvParams) {
	logger := slog.Default()
	mainCtx := CreateMainCtx()
	start := time.Now()
	var cfg ClientConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		logger.Error("failed to parse config", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	if cfg.SrcVault == nil {
		logger.Error("can't perform operation as vault client config is missing")
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info("initializing source vault client", slog.String("host", cfg.SrcVault.BaseURL))
	srcVaultClient, err := initVaultClient(cfg.SrcVault)
	if err != nil {
		logger.Error("failed to initialize vault client", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info("initializing source KV vault", slog.String("mountPath", inputParams.SrcMountPath))
	srcVault, err := srcVaultClient.NewKv2Vault(inputParams.SrcMountPath)
	if err != nil {
		logger.Error(
			"failed to initialize source KV vault",
			slog.String("path", inputParams.SrcMountPath),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	var dstVaultClient *vault.VaultClient
	if cfg.DstVault == nil {
		logger.Info(
			"initializing destination vault client",
			slog.String("host", cfg.SrcVault.BaseURL),
		)
		dstVaultClient, err = initVaultClient(cfg.SrcVault)
	} else {
		logger.Info("initializing destination vault client", slog.String("host", cfg.DstVault.BaseURL))
		dstVaultClient, err = initVaultClient(cfg.DstVault)
	}
	if err != nil {
		logger.Error(
			"failed to initialize destination vault client",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info(
		"initializing destination KV vault",
		slog.String("mountPath", inputParams.DstMountPath),
	)
	dstVault, err := dstVaultClient.NewKv2Vault(inputParams.DstMountPath)
	if err != nil {
		logger.Error("failed to initialize destination KV vault", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info("Collecting secrets for copy")
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	srcPaths, err := getSrcPaths(mainCtx, srcPath, srcVault)
	if err != nil {
		logger.Error(
			"an error occured while collecting paths to copy",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	if inputParams.FilterPaths {
		srcCount := len(srcPaths)
		logger.Info("filtering paths to copy", slog.Int("countBefore", srcCount))
		exp, err := regexp.Compile(inputParams.FilterExpStr)
		if err != nil {
			logger.Error(
				"an error occured while copiling path match expr",
				slog.String("error", err.Error()),
			)
			duration := time.Since(start)
			logger.Info("process duration", slog.Duration("duration", duration))
			os.Exit(10)
		}
		srcPaths = filterSrcPaths(exp, srcPaths)
	}
	secretVersions, err := getMetadataForPaths(mainCtx, srcPaths, inputParams.Versions, srcVault)
	if err != nil {
		logger.Error(
			"an error occured while collecting metadata",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	dstPath := strings.Trim(inputParams.DstPath, "/")
	copyInputs := createCopyVersions(secretVersions, srcPath, dstPath)
	if inputParams.ModDstPaths {
		renameDstPaths(copyInputs, inputParams.OldPathPart, inputParams.NewPathPart)
	}
	copySuccess, copyFails, err := copyRecords(copyInputs, srcVault, dstVault)
	if err != nil {
		logger.Error(
			"an error occured while copying entries",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	failureCount := len(copyFails)
	successCount := len(copySuccess)
	skipFailurePrint := false
	if len(copyFails) == 0 {
		skipFailurePrint = true
	}
	err = srcVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for source vault")
	}
	err = dstVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for destination vault")
	}

	if !skipFailurePrint {
		logger.Info("failed to copy entries", slog.Int("count", failureCount))
		fmt.Println("failed to copy following paths:")
		for _, path := range copyFails {
			fmt.Println(path)
		}
	}
	logger.Info("copy failed", slog.Int("count", failureCount))
	logger.Info("entries copied", slog.Int("count", successCount))
	duration := time.Since(start)
	logger.Info("process duration", slog.Duration("duration", duration))
	logger.Info("done")
}

func startMetadataReaders(
	srcVault *vault.Kv2Vault,
	pathChan chan string,
	verCount int,
) (chan *SecretVersions, *sync.WaitGroup) {
	metadataChan := make(chan *SecretVersions, 50)
	metaReaderGroup := new(sync.WaitGroup)
	processCount := 2
	metaReaderGroup.Add(processCount)
	for range processCount {
		go getMetadata(pathChan, metadataChan, metaReaderGroup, srcVault, verCount)
	}
	go closeMetadataResultChan(metadataChan, metaReaderGroup)
	return metadataChan, metaReaderGroup
}

type SecretVersions struct {
	secretPath string
	versions   []int
}

func getMetadata(
	pathChan chan string,
	metadataChan chan *SecretVersions,
	readerGroup *sync.WaitGroup,
	srcVault *vault.Kv2Vault,
	verCount int,
) {
	logger := slog.Default()
	ctx, cancel := context.WithTimeout(context.TODO(), 60*time.Minute)
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
			logger.Debug("getting metadata from path", slog.String("path", path))
			metadata, err := srcVault.GetSecretMetadata(path)
			if err != nil {
				logger.Error(
					"an error occured while reading metadata from path",
					slog.String("path", path),
					slog.String("error", err.Error()),
				)
				continue
			}
			logger.Debug("filtering secret versions", slog.String("path", path))
			retVal := new(SecretVersions)
			retVal.secretPath = path
			retVal.versions = getSecretVersionsToCopy(*metadata, verCount)
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
	if keep == -1 {
		return validVersions
	}
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
	srcChan chan *SecretVersionsToCopy,
	copyContext *context.Context,
) (chan string, chan string, *sync.WaitGroup) {
	errorChan := make(chan string, 50)
	successChan := make(chan string, 50)
	copierGroup := new(sync.WaitGroup)
	processCount := 2
	copierGroup.Add(processCount)
	for range processCount {
		go copySecrets(
			srcChan,
			successChan,
			errorChan,
			copierGroup,
			srcVault,
			dstVault,
			copyContext,
		)
	}
	go closeCopyChans(successChan, errorChan, copierGroup)
	return successChan, errorChan, copierGroup
}

func closeCopyChans(successChan, errorChan chan string, copyGroup *sync.WaitGroup) {
	defer close(successChan)
	defer close(errorChan)
	copyGroup.Wait()
}

func copySecrets(
	secretChan chan *SecretVersionsToCopy,
	successChan, errorChan chan string,
	copierGroup *sync.WaitGroup,
	srcVault, dstVault *vault.Kv2Vault,
	copyContext *context.Context,

) {
	logger := slog.Default()
	defer copierGroup.Done()
copyLoop:
	for {
		select {
		case <-(*copyContext).Done():
			logger.Error("stopping copying: context timeout reached")
			break copyLoop
		case secretInfo, ok := <-secretChan:
			if !ok {
				logger.Debug("closing copier since input channel has been closed")
				break copyLoop
			}
			for _, versionNum := range secretInfo.versions {
				logger.Debug(
					"reading secret version",
					slog.String("vault", srcVault.DataUrl.Host),
					slog.String("path", secretInfo.origPath),
					slog.Int("version", versionNum),
				)
				secretData, err := srcVault.GetSecretVersion(secretInfo.origPath, versionNum)
				if err != nil {
					errorChan <- secretInfo.origPath
					break
				}
				logger.Debug(
					"writing secret version to destination",
					slog.String("vault", dstVault.DataUrl.Host),
					slog.String("path", secretInfo.newPath),
				)
				err = writeSecretVersion(dstVault, secretData, secretInfo.newPath)
				if err != nil {
					logger.Error("failed to copy secret version", slog.String("path", secretInfo.origPath), slog.Int("version", versionNum))
					errorChan <- secretInfo.origPath
					break
				}
				successChan <- secretInfo.origPath
			}

		}
	}
}

func writeSecretVersion(
	dstVault *vault.Kv2Vault,
	secret *vault.Kv2SecretResp,
	path string,
) error {
	logger := slog.Default()
	data := secret.Data.Data
	err := dstVault.WriteSecret(path, data)
	if err != nil {
		logger.Error(
			"failed to write secret to path",
			slog.String("path", path),
			slog.String("vault", dstVault.DataUrl.Host),
			slog.String("error", err.Error()),
		)
	}

	return err
}

//from move file

func MoveSecrets(inputParams *KvParams) {
	logger := slog.Default()
	mainCtx := CreateMainCtx()
	var cfg ClientConfig
	start := time.Now()
	err := viper.Unmarshal(&cfg)
	if err != nil {
		logger.Error("failed to parse config", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	if cfg.SrcVault == nil {
		logger.Error("can't perform operation as vault client config is missing")
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	srcVaultClient, err := initVaultClient(cfg.SrcVault)
	if err != nil {
		logger.Error("failed to initialize vault client", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	srcVault, err := srcVaultClient.NewKv2Vault(inputParams.SrcMountPath)
	if err != nil {
		logger.Error("failed to initialize kv store", slog.String("path", inputParams.SrcMountPath))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
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
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	dstVault, err := dstVaultClient.NewKv2Vault(inputParams.DstMountPath)
	if err != nil {
		logger.Error("failed to initialize destination vault", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info("Collecting secrets for move")
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	srcPaths, err := getSrcPaths(mainCtx, srcPath, srcVault)
	if err != nil {
		logger.Error(
			"an error occured while getting source paths",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	if inputParams.FilterPaths {
		srcCount := len(srcPaths)
		logger.Info("filtering paths to copy", slog.Int("countBefore", srcCount))
		exp, err := regexp.Compile(inputParams.FilterExpStr)
		if err != nil {
			logger.Error(
				"an error occured while compiling path match expr",
				slog.String("error", err.Error()),
			)
			duration := time.Since(start)
			logger.Info("process duration", slog.Duration("duration", duration))
			os.Exit(10)
		}
		srcPaths = filterSrcPaths(exp, srcPaths)
	}
	secretVersions, err := getMetadataForPaths(mainCtx, srcPaths, inputParams.Versions, srcVault)
	if err != nil {
		logger.Error(
			"an error occured while getting metadata for paths",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	dstPath := strings.Trim(inputParams.DstPath, "/")
	copyInputs := createCopyVersions(secretVersions, srcPath, dstPath)
	if inputParams.ModDstPaths {
		renameDstPaths(copyInputs, inputParams.OldPathPart, inputParams.NewPathPart)
	}
	copySuccess, copyFail, err := copyRecords(copyInputs, srcVault, dstVault)
	if err != nil {
		logger.Error(
			"an error occured while copying entries",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	copyCount := len(copySuccess)
	copyFailCount := len(copyFail)
	skipFailurePrint := false
	shouldDelete := false
	if copyFailCount == 0 {
		skipFailurePrint = true
		shouldDelete = true
	}

	if !skipFailurePrint {
		fmt.Println("failed to copy the following paths during move operation:")
		for _, copyFailedPath := range copyFail {
			fmt.Println(copyFailedPath)
		}
	}
	logger.Info("entries copied", slog.Int("count", copyCount))
	logger.Info("entries failed to copy", slog.Int("count", copyFailCount))

	if shouldDelete {
		deleteSet := NewSet(copySuccess...)
		removePaths := deleteSet.GetValues()
		delSuccess, delFailure, err := deleteRecords(mainCtx, removePaths, srcVault)
		if err != nil {
			logger.Error(
				"an error occured while deleting records",
				slog.String("error", err.Error()),
			)
		}

		delFailureCount := len(delFailure)
		delSuccessCount := len(delSuccess)
		if delFailureCount == 0 {
			fmt.Println("failed to delete the following paths during move operation:")
			for _, delFailedPath := range delFailure {
				fmt.Println(delFailedPath)
			}
		}
		logger.Info("failed to delte paths", slog.Int("count", delFailureCount))
		logger.Info("deleted paths", slog.Int("count", delSuccessCount))
	}
	err = srcVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for source vault")
	}
	err = dstVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for destination vault")
	}
	duration := time.Since(start)
	logger.Info("process duration", slog.Duration("duration", duration))
	logger.Info("done")
}

//from list file

// func ListSecrets() {
// 	logger := slog.Default()
// 	var cfg ClientConfig
// 	err := viper.Unmarshal(&cfg)
// 	if err != nil {
// 		logger.Error("an error occured while reading config", slog.String("error", err.Error()))
// 		os.Exit(10)
// 	}
// 	if cfg.SrcVault == nil {
// 		logger.Error("source vault info missing... terminating")
// 		os.Exit(10)
// 	}
// 	client, err := vault.NewClient(cfg.SrcVault.BaseURL)
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// 	err = client.WithUserAuth(cfg.SrcVault.UserCreds.Username, cfg.SrcVault.UserCreds.Password, "")
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// 	err = client.Authenticate()
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// 	kv2Vault, err := client.NewKv2Vault("secret")
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// 	secretChan := kv2Vault.GetSecretPaths("")
// 	paths := make([]string, 0)
// 	for result := range secretChan {
// 		paths = append(paths, result)
// 	}

// 	fmt.Println("paths:")
// 	for _, v := range paths {
// 		fmt.Println(v)
// 	}

// }

//from delete file

type DeleteParams struct {
	SrcMountPath string
	SrcPath      string
}

func DeleteSecrets(inputParams DeleteParams) {
	logger := slog.Default()
	mainCtx := CreateMainCtx()
	start := time.Now()
	var cfg ClientConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		logger.Error("failed to parse config", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	if cfg.SrcVault == nil {
		logger.Error("can't perform operation as vault client config is missing")
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info("initializing vault client", slog.String("host", cfg.SrcVault.BaseURL))
	srcClient, err := initVaultClient(cfg.SrcVault)
	if err != nil {
		logger.Error("failed to initialize vault client", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info("initializing KV vault", slog.String("mountPath", inputParams.SrcMountPath))
	srcVault, err := srcClient.NewKv2Vault(inputParams.SrcMountPath)
	if err != nil {
		logger.Error("failed to initialize vault", slog.String("path", inputParams.SrcMountPath))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	logger.Info("Collecting secrets for deletion")
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	srcPaths, err := getSrcPaths(mainCtx, srcPath, srcVault)
	if err != nil {
		logger.Error(
			"failed to get source paths for records",
			slog.String("path", srcPath),
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	delSuccess, delFailure, err := deleteRecords(mainCtx, srcPaths, srcVault)
	if err != nil {
		logger.Error("an error occured while deleting records", slog.String("error", err.Error()))
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	successCount := len(delSuccess)
	failureCount := len(delFailure)
	logger.Info("paths deleted", slog.Int("count", successCount))
	logger.Info("paths failed to delete", slog.Int("count", failureCount))
	if failureCount > 0 {
		fmt.Println("failed to delete following paths:")
		for _, path := range delFailure {
			fmt.Println(path)
		}
	}
	if logger.Handler().Enabled(context.TODO(), slog.LevelDebug) {
		if successCount > 0 {
			fmt.Println("successfully deleted following paths:")
			for _, path := range delSuccess {
				fmt.Println(path)
			}
		}
	}
	duration := time.Since(start)
	logger.Info("process duration", slog.Duration("duration", duration))
	logger.Info("done")
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
	if vaultCfg.Insecure {
		err = vaultClient.Insecure()
	}
	if err != nil {
		msg := fmt.Errorf("failed to set connection to insecure: %w", err)
		return nil, msg
	}
	switch vaultCfg.AuthType {
	case "userpass":
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
	case "ldap":
		err = vaultClient.WithLdapAuth(vaultCfg.UserCreds.Username, vaultCfg.UserCreds.Password, "")
		if err != nil {
			msg := fmt.Errorf("vault authentication failed: %w", err)
			return nil, msg
		}
		err = vaultClient.Authenticate()
		if err != nil {
			msg := fmt.Errorf("an error occured while performing authentication to vault: %w", err)
			return nil, msg
		}
	case "token":
		err = vaultClient.WithTokenAuth(vaultCfg.TokenCreds.Token)
		if err != nil {
			msg := fmt.Errorf("vault authentication failed: %w", err)
			return nil, msg
		}
	default:
		return nil, fmt.Errorf("unsupported authentication method specified")
	}
	return vaultClient, nil
}

func startDeleteWorkers(
	srcVault *vault.Kv2Vault,
	deleteChan chan string,
) (chan string, chan string, *sync.WaitGroup) {
	deleteGroup := new(sync.WaitGroup)
	successChan := make(chan string, 100)
	errorChan := make(chan string, 100)

	processCount := 2
	deleteGroup.Add(processCount)
	for range processCount {
		go shouldDelete(srcVault, deleteChan, successChan, errorChan, deleteGroup)
	}
	return successChan, errorChan, deleteGroup
}

func shouldDelete(
	srcVault *vault.Kv2Vault,
	pathChan, successChan, errorChan chan string,
	deleteGroup *sync.WaitGroup,
) {
	logger := slog.Default()
	ctx, ctxCancel := context.WithTimeout(context.TODO(), 60*time.Minute)
	defer deleteGroup.Done()
	defer ctxCancel()
deleteLoop:
	for {
		select {
		case <-ctx.Done():
			logger.Error("stopping deletion: context timeout reached")
			break deleteLoop
		case path, ok := <-pathChan:
			if !ok {
				logger.Debug("terminating delete processor as input channel closed")
				break deleteLoop
			}
			logger.Debug("deleting secret", slog.String("path", path))
			err := srcVault.DeletSecret(path)
			if err != nil {
				logger.Error("failed to delete secret", slog.String("path", path))
				errorChan <- path
			} else {
				successChan <- path
			}
		}
	}
}

func startPathResolveWorkers(
	srcVault *vault.Kv2Vault,
	sender *DataSender[string],
) (chan string, *sync.WaitGroup) {
	secretChan := make(chan string, 100)
	pathGroup := new(sync.WaitGroup)
	processorCount := 2
	pathGroup.Add(processorCount)
	for range processorCount {
		go getSecretPathsFromPath(srcVault, secretChan, pathGroup, sender)
	}
	go closePathLookupChans(secretChan, pathGroup)
	return secretChan, pathGroup
}

func getSecretPathsFromPath(
	srcVault *vault.Kv2Vault,
	respChan chan string,
	pathGroup *sync.WaitGroup,
	sender *DataSender[string],
) {
	logger := slog.Default()
	ctx := sender.GetContext()
	rcvChan := sender.GetChannel()
	defer pathGroup.Done()
pathLookup:
	for {
		select {
		case <-(*ctx).Done():
			logger.Error("path processor context timeout")
			break pathLookup
		case path, ok := <-rcvChan:
			if !ok {
				logger.Debug("terminating path processor as input channel is closed")
				break pathLookup
			}
			logger.Debug("listing items from path", slog.String("path", path))
			secrets, folders, err := srcVault.ListPath(path)
			if err != nil {
				logger.Error("an error occured while listing path", slog.String("path", path), slog.String("error", err.Error()))
				continue pathLookup
			}
			for _, secret := range secrets {
				respChan <- secret
			}
			if len(folders) > 0 {
				sender.Append(folders)
			}
		}
	}
}

func closePathLookupChans(respChan chan string, pathGroup *sync.WaitGroup) {
	defer close(respChan)
	pathGroup.Wait()
}

type ResultCollector[T any] struct {
	resItems     []T
	resChan      chan T
	collectError error
	ctx          context.Context
}

func NewResCollector[T any](ctx context.Context, results chan T) *ResultCollector[T] {
	output := new(ResultCollector[T])
	output.resChan = results
	output.ctx = ctx
	return output
}
func (r *ResultCollector[T]) StartCollect(resType string) {
	logger := slog.Default()
	msg := fmt.Sprintf("%s collected", resType)
	collectTicker := time.NewTicker(10 * time.Second)
	r.resItems = make([]T, 0)

collectLoop:
	for {
		select {
		case <-r.ctx.Done():
			r.collectError = fmt.Errorf("collect context terminated with error: %w", r.ctx.Err())
			break collectLoop

		case res, ok := <-r.resChan:
			if !ok {
				logger.Debug("terminating result collector since result channel is closed")
				break collectLoop
			}
			r.resItems = append(r.resItems, res)
		case <-collectTicker.C:
			resultsCollected := len(r.resItems)
			logger.Info(msg, slog.Int("count", resultsCollected))
		}
	}
}

func (r *ResultCollector[T]) GetResults() ([]T, error) {
	if r.collectError != nil {
		return nil, r.collectError
	}
	if len(r.resItems) > 0 {
		return r.resItems, nil
	}
	return nil, nil
}

type DataSender[T any] struct {
	sendChan   chan T
	inputVals  []T
	operLock   sync.Mutex
	sendTimer  *time.Ticker
	reloadData bool
	ctx        context.Context
	senderErr  error
	chanLength int
}

func NewDataSender[T any](
	chanSize int,
	delay time.Duration,
	inputs []T,
	ctx context.Context,
) *DataSender[T] {
	senderChan := make(chan T, chanSize)
	pulseLength := 100 * time.Millisecond
	if delay != 0 {
		pulseLength = delay
	}
	ticker := time.NewTicker(pulseLength)
	sender := DataSender[T]{
		sendChan:   senderChan,
		inputVals:  inputs,
		sendTimer:  ticker,
		ctx:        ctx,
		chanLength: chanSize,
	}
	return &sender
}

func (d *DataSender[T]) GetContext() *context.Context {
	return &d.ctx
}
func (d *DataSender[T]) GetChannel() chan T {
	return d.sendChan
}

func (d *DataSender[T]) Start() {
	loopCounter := 0
processLoop:
	for {
		d.operLock.Lock()
		if len(d.inputVals) == 0 && len(d.sendChan) == 0 && loopCounter > 10 {
			d.operLock.Unlock()
			break processLoop
		}
		select {
		case <-d.ctx.Done():
			d.senderErr = fmt.Errorf("context canceled: %w", d.ctx.Err())
			d.operLock.Unlock()
			break processLoop
		case <-d.sendTimer.C:
			if d.reloadData {
				d.operLock.Unlock()
				continue processLoop
			}
			if len(d.inputVals) > 0 && len(d.sendChan) < d.chanLength {
				d.sendChan <- d.inputVals[0]
				loopCounter = 0
			} else if len(d.inputVals) == 0 {
				time.Sleep(100 * time.Millisecond)
			}
		}
		if len(d.inputVals) > 0 {
			d.inputVals = slices.Delete(d.inputVals, 0, 1)
		}
		loopCounter++
		d.operLock.Unlock()
	}
	close(d.sendChan)
}

func (d *DataSender[T]) Append(newVals []T) {
	d.reloadData = true
	d.operLock.Lock()
	d.inputVals = append(d.inputVals, newVals...)
	d.reloadData = false
	d.operLock.Unlock()
}

func (d *DataSender[T]) CheckErr() error {
	if d.senderErr != nil {
		return d.senderErr
	}
	return nil
}

func filterSrcPaths(matchExp *regexp.Regexp, secretPaths []string) []string {
	filteredPaths := make([]string, 0)
	for _, path := range secretPaths {
		matchRes := matchExp.FindAllString(path, 1)
		if matchRes == nil {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func renameDstPaths(versions []*SecretVersionsToCopy, srcPart, dstPart string) {
	for _, version := range versions {
		entityParts := strings.Split(version.newPath, "/")
		newPathLen := len(entityParts)
		entityName := entityParts[newPathLen-1]
		pathParts := entityParts[0 : newPathLen-1]
		path := strings.Join(pathParts, "/")
		path = strings.ReplaceAll(path, srcPart, dstPart)
		path = strings.Trim(path, "/")
		version.newPath = fmt.Sprintf("%s/%s", path, entityName)
	}
}

func createCopyVersions(
	versionInfos []*SecretVersions,
	srcPath, dstPath string,
) []*SecretVersionsToCopy {
	versionsToCopy := make([]*SecretVersionsToCopy, 0)
	for _, versionInfo := range versionInfos {
		trimmedPath := strings.TrimPrefix(versionInfo.secretPath, srcPath)
		copyInfo := &SecretVersionsToCopy{
			origPath: versionInfo.secretPath,
			versions: versionInfo.versions,
			newPath:  fmt.Sprintf("%s%s", dstPath, trimmedPath),
		}
		versionsToCopy = append(versionsToCopy, copyInfo)
	}
	return versionsToCopy
}

func getSrcPaths(ctx context.Context, srcPath string, srcVault *vault.Kv2Vault) ([]string, error) {
	logger := slog.Default()
	logger.Info("resolving paths for operation")
	initialInput := []string{srcPath}
	processCtx, ProcessCtxCancel := context.WithTimeout(ctx, 1*time.Hour)
	pathSender := NewDataSender(20, 40*time.Millisecond, initialInput, processCtx)
	srcPathChan, srcCollectorGroup := startPathResolveWorkers(srcVault, pathSender)
	srcPathCollector := NewResCollector(processCtx, srcPathChan)
	go pathSender.Start()
	go srcPathCollector.StartCollect("paths resolved")
	srcCollectorGroup.Wait()
	ProcessCtxCancel()
	err := pathSender.CheckErr()
	if err != nil {
		return nil, fmt.Errorf(
			"an error occured while processing secret paths: %w", err)
	}
	srcPaths, err := srcPathCollector.GetResults()
	if err != nil {
		return nil, fmt.Errorf("an error occured while collecting results: %w", err)
	}
	return srcPaths, nil
}

func getMetadataForPaths(
	ctx context.Context,
	srcPaths []string,
	verCount int,
	srcVault *vault.Kv2Vault,
) ([]*SecretVersions, error) {
	logger := slog.Default()
	srcCount := len(srcPaths)
	logger.Info("starting metadata collection", slog.Int("count", srcCount))
	metaReaderCtx, metaReaderCtxCancel := context.WithTimeout(ctx, 1*time.Hour)
	metadataPathSender := NewDataSender(20, 20*time.Millisecond, srcPaths, metaReaderCtx)
	metadataChan, metaReaderGroup := startMetadataReaders(
		srcVault,
		metadataPathSender.GetChannel(),
		verCount,
	)
	go metadataPathSender.Start()
	secretVerCollector := NewResCollector(metaReaderCtx, metadataChan)
	secretVerCollector.StartCollect("metadata for copy")
	metaReaderGroup.Wait()
	metaReaderCtxCancel()
	err := metadataPathSender.CheckErr()
	if err != nil {
		return nil, fmt.Errorf(
			"an error occured while processing secret metadata: %w", err)
	}
	secretVersions, err := secretVerCollector.GetResults()
	if err != nil {
		return nil, fmt.Errorf("an error occured while collecting metadata results: %w", err)
	}
	secretVerCollector = nil
	metadataPathSender = nil

	return secretVersions, nil
}

func copyRecords(
	srcObjs []*SecretVersionsToCopy,
	srcVault, dstVault *vault.Kv2Vault,
) ([]string, []string, error) {
	logger := slog.Default()
	secretsToCopy := len(srcObjs)
	logger.Info("starting secret copy", slog.Int("count", secretsToCopy))
	copyCtx, copyCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	copySender := NewDataSender(20, 20*time.Millisecond, srcObjs, copyCtx)
	successChan, errorChan, copierGroup := startSecretCopiers(
		srcVault,
		dstVault,
		copySender.GetChannel(),
		&copyCtx,
	)
	go copySender.Start()
	failureCollector := NewResCollector(copyCtx, errorChan)
	go failureCollector.StartCollect("paths/versions copy failed")
	successCollector := NewResCollector(copyCtx, successChan)
	go successCollector.StartCollect("paths/versions copy succeeded")
	copierGroup.Wait()
	copyCtxCancel()
	err := copySender.CheckErr()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"an error occured while procesing secrets to copy: %w", err)
	}
	copySender = nil
	failedPaths, err := failureCollector.GetResults()
	if err != nil {
		return nil, nil, fmt.Errorf("collecting copy failures had an error: %w", err)
	}
	failureCollector = nil
	successfulPaths, err := successCollector.GetResults()
	if err != nil {
		return nil, nil, fmt.Errorf("collecting copy successes had an error: %w", err)
	}
	successCollector = nil

	return successfulPaths, failedPaths, nil
}

func deleteRecords(
	ctx context.Context,
	removePaths []string,
	srcVault *vault.Kv2Vault,
) ([]string, []string, error) {
	logger := slog.Default()
	deleteCount := len(removePaths)
	logger.Info("starting secret deletion", slog.Int("count", deleteCount))
	deleteCtx, deleteCtxCancel := context.WithTimeout(ctx, 1*time.Hour)
	deleteSender := NewDataSender(20, 40*time.Millisecond, removePaths, deleteCtx)
	go deleteSender.Start()
	successChan, errorChan, deleteGroup := startDeleteWorkers(
		srcVault,
		deleteSender.GetChannel(),
	)
	delFailureCollector := NewResCollector(deleteCtx, errorChan)
	go delFailureCollector.StartCollect("delete failures")
	delSuccessCollector := NewResCollector(deleteCtx, successChan)
	go delSuccessCollector.StartCollect("paths deleted")

	deleteGroup.Wait()
	deleteCtxCancel()
	err := deleteSender.CheckErr()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"an error occured while processing secret deletions: %w", err)
	}
	delSuccess, err := delSuccessCollector.GetResults()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to collect successfull deletion results: %w", err)
	}
	delFailure, err := delFailureCollector.GetResults()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to collect failed deletion results: %w", err)
	}

	return delSuccess, delFailure, nil
}
