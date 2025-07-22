package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lazah/vault-cli-go/internal/vault"
	"github.com/spf13/viper"
)

//from copy file

type CopyParams struct {
	SrcPath      string
	DstPath      string
	SrcMountPath string
	DstMountPath string
	Versions     int
}

func CopySecrets(inputParams CopyParams) {
	logger := slog.Default()
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
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	logger.Info("resolving paths to copy")
	pathSenderCtx, pathSenderCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	initialInput := []string{srcPath}
	pathSender := NewDataSender(20, 40*time.Millisecond, initialInput, pathSenderCtx)
	srcPathChan, srcCollectorGroup := startPathResolveWorkers(srcVault, pathSender)
	srcPathCollector := &ResultCollector[string]{
		resChan:      srcPathChan,
		collectError: nil,
	}
	go pathSender.Start()
	go srcPathCollector.StartCollect("paths to copy")
	srcCollectorGroup.Wait()
	pathSenderCtxCancel()
	srcPaths, err := srcPathCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting paths to copy",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	pathSender = nil
	srcPathCollector = nil
	srcCount := len(srcPaths)
	logger.Info("starting metadata collection", slog.Int("count", srcCount))
	metaReaderCtx, metaReaderCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	metadataPathSender := NewDataSender(20, 20*time.Millisecond, srcPaths, metaReaderCtx)
	metadataChan, metaReaderGroup := startMetadataReaders(
		srcVault,
		metadataPathSender.GetChannel(),
		inputParams.Versions,
	)
	go metadataPathSender.Start()
	secretVerCollector := &ResultCollector[*SecretVersions]{
		resChan:      metadataChan,
		collectError: nil,
	}
	secretVerCollector.StartCollect("metadata for copy")
	metaReaderGroup.Wait()
	metaReaderCtxCancel()
	secretVersions, err := secretVerCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting metadata",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	secretVerCollector = nil
	metadataPathSender = nil
	secretsToCopy := len(secretVersions)
	logger.Info("starting secret copy", slog.Int("secretCount", secretsToCopy))
	dstPath := strings.Trim(inputParams.DstPath, "/")
	copyInputs := make([]*SecretVersionsToCopy, 0)
	for _, secretVersion := range secretVersions {
		trimmedPath := strings.TrimPrefix(secretVersion.secretPath, srcPath)
		versionInfo := &SecretVersionsToCopy{
			origPath: secretVersion.secretPath,
			versions: secretVersion.versions,
			newPath:  fmt.Sprintf("%s%s", dstPath, trimmedPath),
		}
		copyInputs = append(copyInputs, versionInfo)
	}
	copyCtx, copyCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	copySender := NewDataSender(20, 20*time.Millisecond, copyInputs, copyCtx)
	successChan, errorChan, copierGroup := startSecretCopiers(
		srcVault,
		dstVault,
		copySender.GetChannel(),
		&copyCtx,
	)
	go copySender.Start()
	failureCollector := &ResultCollector[string]{
		resChan:      errorChan,
		collectError: nil,
	}
	go failureCollector.StartCollect("copy failures")
	successCollector := &ResultCollector[string]{
		resChan:      successChan,
		collectError: nil,
	}
	go successCollector.StartCollect("paths copied")
	skipFailurePrint := false
	copierGroup.Wait()
	copyCtxCancel()
	err = copySender.CheckErr()
	if err != nil {
		logger.Error(
			"an error occured while procesing secrets to copy: ",
			slog.String("error", err.Error()),
		)
	}
	copySender = nil
	failedPaths, err := failureCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting copy failures",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	failureCollector = nil
	successfulPaths, err := successCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting copy successes",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	successCollector = nil
	if len(failedPaths) == 0 {
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
	failureCount := len(failedPaths)
	logger.Info("copy failed", slog.Int("count", failureCount))
	if !skipFailurePrint {
		logger.Info("failed to copy entries", slog.Int("count", failureCount))
		fmt.Println("failed to copy following paths:")
		for _, path := range failedPaths {
			fmt.Println(path)
		}
	}
	successCount := len(successfulPaths)
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
		go getMetadataForPaths(pathChan, metadataChan, metaReaderGroup, srcVault, verCount)
	}
	go closeMetadataResultChan(metadataChan, metaReaderGroup)
	return metadataChan, metaReaderGroup
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
	go closeCopyChans(errorChan, copierGroup)
	return successChan, errorChan, copierGroup
}

func closeCopyChans(errorChan chan string, copyGroup *sync.WaitGroup) {
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

func MoveSecrets(inputParams *CopyParams) {
	logger := slog.Default()
	var cfg ClientConfig
	start := time.Now()
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
	pathSenderCtx, pathSenderCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	initialInput := []string{srcPath}
	pathSender := NewDataSender(20, 40*time.Millisecond, initialInput, pathSenderCtx)
	go pathSender.Start()
	srcPathChan, srcCollectorGroup := startPathResolveWorkers(srcVault, pathSender)
	srcPathCollector := &ResultCollector[string]{
		resChan:      srcPathChan,
		collectError: nil,
	}
	go srcPathCollector.StartCollect("paths to move")
	srcCollectorGroup.Wait()
	pathSenderCtxCancel()
	srcPaths, err := srcPathCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting paths to copy",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	pathSender = nil
	srcPathCollector = nil
	srcCount := len(srcPaths)
	logger.Info("starting metadata collection", slog.Int("count", srcCount))
	metaReaderCtx, metaReaderCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	metadataPathSender := NewDataSender(20, 20*time.Millisecond, srcPaths, metaReaderCtx)
	go metadataPathSender.Start()
	metadataChan, metaReaderGroup := startMetadataReaders(
		srcVault,
		metadataPathSender.GetChannel(),
		inputParams.Versions,
	)
	secretVerCollector := &ResultCollector[*SecretVersions]{
		resChan:      metadataChan,
		collectError: nil,
	}
	secretVerCollector.StartCollect("metadata for move")
	metaReaderGroup.Wait()
	metaReaderCtxCancel()
	secretVersions, err := secretVerCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting metadata",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	metadataPathSender = nil
	secretVerCollector = nil
	secretsToCopy := len(secretVersions)
	logger.Info("starting secret copy", slog.Int("count", secretsToCopy))
	dstPath := strings.Trim(inputParams.DstPath, "/")
	copyInputs := make([]*SecretVersionsToCopy, 0)
	for _, secretVersion := range secretVersions {
		trimmedPath := strings.TrimPrefix(secretVersion.secretPath, srcPath)
		versionInfo := &SecretVersionsToCopy{
			origPath: secretVersion.secretPath,
			versions: secretVersion.versions,
			newPath:  fmt.Sprintf("%s%s", dstPath, trimmedPath),
		}
		copyInputs = append(copyInputs, versionInfo)
	}
	copyCtx, copyCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	copySender := NewDataSender(20, 40*time.Millisecond, copyInputs, copyCtx)
	successChan, errorChan, copierGroup := startSecretCopiers(
		srcVault,
		dstVault,
		copySender.GetChannel(),
		&copyCtx,
	)
	go copySender.Start()
	copyfailureCol := &ResultCollector[string]{
		resChan:      errorChan,
		collectError: nil,
	}
	go copyfailureCol.StartCollect("copy failures")
	copySuccessCol := &ResultCollector[string]{
		resChan:      successChan,
		collectError: nil,
	}
	go copySuccessCol.StartCollect("paths copied")
	copierGroup.Wait()
	copyCtxCancel()
	skipFailurePrint := false
	deleteSecrets := true
	copyFailedPaths, err := copyfailureCol.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting copy failures",
			slog.String("error", err.Error()),
		)
		deleteSecrets = false
	}
	copySender = nil
	copyfailureCol = nil
	if len(copyFailedPaths) == 0 {
		skipFailurePrint = true
	}

	if !skipFailurePrint {
		fmt.Println("failed to copy the following paths during move operation:")
		for _, copyFailedPath := range copyFailedPaths {
			fmt.Println(copyFailedPath)
		}
	}

	if deleteSecrets {
		removePaths, err := copySuccessCol.GetResults()
		if err != nil {
			logger.Error(
				"an error occured while collecting copy sucesses",
				slog.String("error", err.Error()),
			)
		}
		copySuccessCol = nil
		deleteCount := len(removePaths)
		logger.Info("starting secret deletion", slog.Int("count", deleteCount))
		deleteCtx, deleteCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
		deleteSender := NewDataSender(20, 40*time.Millisecond, removePaths, deleteCtx)
		go deleteSender.Start()
		successChan, errorChan, deleteGroup := startDeleteWorkers(
			srcVault,
			deleteSender.GetChannel(),
		)
		delFailureCollector := &ResultCollector[string]{
			resChan:      errorChan,
			collectError: nil,
		}
		go delFailureCollector.StartCollect("delete failures")
		delSuccessCollector := &ResultCollector[string]{
			resChan:      successChan,
			collectError: nil,
		}
		go delSuccessCollector.StartCollect("paths deleted")

		deleteGroup.Wait()
		deleteCtxCancel()
		deleteSender = nil
		_, err = delSuccessCollector.GetResults()
		if err != nil {
			logger.Error(
				"an error occured while collecting succeeded deletions",
				slog.String("error", err.Error()),
			)
		}
		delSuccessCollector = nil
		delFailedPaths, err := delFailureCollector.GetResults()
		if err != nil {
			logger.Error(
				"an error occured while collecting failed deletions",
				slog.String("error", err.Error()),
			)
		}
		delFailureCollector = nil
		if len(delFailedPaths) == 0 {
			fmt.Println("failed to delete the following paths during move operation:")
			for _, copyFailedPath := range copyFailedPaths {
				fmt.Println(copyFailedPath)
			}
		}
	}
	err = srcVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for source vault")
	}
	err = dstVaultClient.RevokeToken()
	if err != nil {
		logger.Warn("failed to revoke session token for destination vault")
	}
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
	srcPath := strings.Trim(inputParams.SrcPath, "/")
	logger.Info("resolving paths to delete")
	pathSenderCtx, pathSenderCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	initialInput := []string{srcPath}
	pathSender := NewDataSender(20, 40*time.Millisecond, initialInput, pathSenderCtx)
	srcPathChan, srcCollectorGroup := startPathResolveWorkers(srcVault, pathSender)
	srcPathCollector := &ResultCollector[string]{
		resChan:      srcPathChan,
		collectError: nil,
	}
	go pathSender.Start()
	go srcPathCollector.StartCollect("paths to delete")
	srcCollectorGroup.Wait()
	pathSenderCtxCancel()
	pathsToDelete, err := srcPathCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting secret paths for deletion",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	pathSender = nil
	srcPathCollector = nil
	deleteCount := len(pathsToDelete)
	logger.Info("starting secret deletion", slog.Int("count", deleteCount))
	secretDeleteCtx, secretDeleteCtxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	deleteSender := NewDataSender(20, 20*time.Millisecond, pathsToDelete, secretDeleteCtx)
	go deleteSender.Start()
	successChan, errorChan, deleteGroup := startDeleteWorkers(srcVault, deleteSender.GetChannel())
	successCollector := &ResultCollector[string]{
		resChan:      successChan,
		collectError: nil,
	}
	failureCollector := &ResultCollector[string]{
		resChan:      errorChan,
		collectError: nil,
	}
	go successCollector.StartCollect("deleted paths")
	go failureCollector.StartCollect("delete failures")
	deleteGroup.Wait()
	secretDeleteCtxCancel()
	successes, err := successCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting deletion results",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
	}
	deleteSender = nil
	successCollector = nil
	failures, err := failureCollector.GetResults()
	if err != nil {
		logger.Error(
			"an error occured while collecting deletion results",
			slog.String("error", err.Error()),
		)
		duration := time.Since(start)
		logger.Info("process duration", slog.Duration("duration", duration))
		os.Exit(10)
		err = srcClient.RevokeToken()
		if err != nil {
			logger.Error("failed to revoke session token")
		}
	}
	failureCollector = nil
	successCount := len(successes)
	failureCount := len(failures)
	logger.Info("paths deleted", slog.Int("count", successCount))
	logger.Info("paths failed to delete", slog.Int("count", failureCount))
	if failureCount > 0 {
		fmt.Println("failed to delete following paths:")
		for _, path := range failures {
			fmt.Println(path)
		}
	}
	if logger.Handler().Enabled(context.TODO(), slog.LevelDebug) {
		if successCount > 0 {
			fmt.Println("successfully deleted following paths:")
			for _, path := range successes {
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
		go deleteSecrets(srcVault, deleteChan, successChan, errorChan, deleteGroup)
	}
	return successChan, errorChan, deleteGroup
}

func deleteSecrets(
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
}

func (r *ResultCollector[T]) StartCollect(resType string) {
	logger := slog.Default()
	msg := fmt.Sprintf("%s collected", resType)
	collectTicker := time.NewTicker(10 * time.Second)
	ctx, ctxCancel := context.WithTimeout(context.TODO(), 2*time.Hour)
	r.resItems = make([]T, 0)

collectLoop:
	for {
		select {
		case <-ctx.Done():
			r.collectError = fmt.Errorf("collect context terminated: %w", ctx.Err())
			break collectLoop

		case res, ok := <-r.resChan:
			if !ok {
				logger.Debug("terminating result collector since result channel is closed")
				ctxCancel()
				break collectLoop
			}
			r.resItems = append(r.resItems, res)
		case <-collectTicker.C:
			resultsCollected := len(r.resItems)
			logger.Info(msg, slog.Int("count", resultsCollected))
		}
	}
	ctxCancel()
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
	return nil
}
