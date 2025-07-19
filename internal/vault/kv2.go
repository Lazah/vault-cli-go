package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"
)

func (k *Kv2Vault) ListPath(secretPath string) ([]string, []string, error) {
	logger := slog.Default()
	escapedSecretPath := escapeRequestPath(secretPath)
	pathUrl, err := k.MetaDataUrl.Parse(escapedSecretPath)
	if err != nil {
		return nil, nil, err
	}
	guardTime := time.Now().Add(60 * time.Second)
	logger.Debug(
		"checking token against date",
		slog.String("guardDate", guardTime.Format(time.RFC3339)),
	)
	expired := guardTime.After(k.VaultClient.sessionToken.exp)
	if expired {
		k.VaultClient.sessionToken.tokenMutex.Lock()
		expired := guardTime.After(k.VaultClient.sessionToken.exp)
		if expired {
			err = k.checkToken()
			if err != nil {
				msg := fmt.Errorf("token check failed: %w", err)
				k.VaultClient.sessionToken.tokenMutex.Unlock()
				return nil, nil, msg
			}
		}
		time.Sleep(1 * time.Second)
		k.VaultClient.sessionToken.tokenMutex.Unlock()
	}
	k.operLock.RLock()
	req := k.VaultClient.apiClient.NewRequest()
	resp, err := req.Execute("LIST", pathUrl.String())
	k.operLock.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	if resp.IsError() {
		return nil, nil, fmt.Errorf("request failed %s", resp.Status())
	}
	var respBody Kv2ListResponse
	err = json.Unmarshal(resp.Body(), &respBody)
	if err != nil {
		return nil, nil, err
	}
	tempPaths, ok := respBody.Data["keys"]
	if !ok {
		return nil, nil, fmt.Errorf("someting somethin dark side")
	}
	paths := make([]string, 0)
	for _, v := range tempPaths.([]any) {
		val := v.(string)
		path := fmt.Sprintf("%s/%s", secretPath, val)
		paths = append(paths, path)
	}
	secrets, folders := splitPaths(paths)
	return secrets, folders, nil
}

type Kv2Resp struct {
	RequestId     string         `json:"request_id,omitempty"`
	LeaseId       string         `json:"lease_id,omitempty"`
	LeaseDuration int            `json:"lease_duration,omitempty"`
	Renewable     bool           `json:"renewable,omitempty"`
	MountType     string         `json:"mount_type,omitempty"`
	WrapInfo      map[string]any `json:"wrap_info,omitempty"`
	Warnings      []string       `json:"warnings,omitempty"`
	Auth          *VaultAuth     `json:"auth,omitempty"`
}
type VaultAuth struct {
	ClientToken   string            `json:"client_token,omitempty"`
	Accessor      string            `json:"accessor,omitempty"`
	Policies      []string          `json:"policies,omitempty"`
	TokenPolicies []string          `json:"token_policies,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	LeaseDuration int               `json:"lease_duration,omitempty"`
	Renewable     bool              `json:"renewable,omitempty"`
	EntityId      string            `json:"entity_id,omitempty"`
	TokenType     string            `json:"token_type,omitempty"`
	Orphan        bool              `json:"orphan,omitempty"`
	NumUses       int               `json:"num_uses,omitempty"`
}

/*
   "entity_id": "248f704f-5da9-4718-4af7-0874395c002e",
   "token_type": "service",
   "orphan": true,
   "mfa_requirement": null,
   "num_uses": 0
*/

func splitPaths(paths []string) ([]string, []string) {
	folders := make([]string, 0)
	secrets := make([]string, 0)
	for _, v := range paths {
		lastIndex := strings.LastIndex(v, "/")
		if lastIndex == len(v)-1 {
			folders = append(folders, v[:len(v)-1])
			continue
		}
		secrets = append(secrets, v)
	}
	return secrets, folders
}

type Kv2Vault struct {
	VaultClient *VaultClient
	MountPath   string
	MetaDataUrl *url.URL
	DataUrl     *url.URL
	operLock    *sync.RWMutex
}

func (c *VaultClient) NewKv2Vault(mountPath string) (*Kv2Vault, error) {
	metadataPath := fmt.Sprintf("v1/%s/metadata/", mountPath)
	dataPath := fmt.Sprintf("v1/%s/data/", mountPath)
	metadataUrl, err := c.baseUrl.Parse(metadataPath)
	if err != nil {
		return nil, err
	}
	dataUrl, err := c.baseUrl.Parse(dataPath)
	if err != nil {
		return nil, err
	}
	rwMutex := new(sync.RWMutex)
	return &Kv2Vault{
		VaultClient: c,
		MountPath:   mountPath,
		MetaDataUrl: metadataUrl,
		DataUrl:     dataUrl,
		operLock:    rwMutex,
	}, nil
}

func (k *Kv2Vault) GetSecretPaths(startPath string) chan string {
	secretChan := make(chan string, 100)
	pathChan := make(chan string, 1000)
	pathGroup := new(sync.WaitGroup)
	processorCount := 4
	pathGroup.Add(processorCount)
	pathChan <- startPath
	for range processorCount {
		go k.getSecretPathsFromPath(secretChan, pathChan, pathGroup)
	}
	go k.closePathLookupChans(secretChan, pathChan, pathGroup)
	return secretChan
}

func (k *Kv2Vault) getSecretPathsFromPath(
	respChan, pathChan chan string,
	pathGroup *sync.WaitGroup,
) {
	logger := slog.Default()
	ctx, cancel := context.WithTimeout(k.VaultClient.ctx, 60*time.Hour)
	loopCounter := 0
	defer pathGroup.Done()
pathLookup:
	for {
		select {
		case <-ctx.Done():
			logger.Error("path processor context timeout")
			cancel()
			break pathLookup
		case path := <-pathChan:
			logger.Info("getting keys from path", slog.String("path", path))
			secrets, folders, err := k.ListPath(path)
			if err != nil {
				logger.Error(
					"an error occured while listing path",
					slog.String("path", path),
					slog.String("error", err.Error()),
				)
			}
			for _, folder := range folders {
				pathChan <- folder
			}
			for _, secret := range secrets {
				respChan <- secret
			}
			loopCounter = 0
		default:
			if loopCounter > 4 {
				cancel()
				logger.Debug("terminating path processor as no work is queued for 5 cycles")
				break pathLookup
			}
			if len(pathChan) == 0 {
				loopCounter++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func (k *Kv2Vault) closePathLookupChans(respChan, pathChan chan string, pathGroup *sync.WaitGroup) {
	defer close(pathChan)
	defer close(respChan)
	pathGroup.Wait()
}

func (k *Kv2Vault) checkToken() error {
	vault := fmt.Sprintf("%s/%s", k.VaultClient.baseUrl.String(), k.MountPath)
	logger := slog.Default().With("vault", vault)
	guardTime := time.Now().Add(60 * time.Second)
	expired := guardTime.After(k.VaultClient.sessionToken.exp)
	if !expired && !k.VaultClient.sessionToken.maxTtl {
		return nil
	}
	k.operLock.Lock()
	if k.VaultClient.sessionToken.maxTtl && expired {
		err := k.VaultClient.Authenticate()
		if err != nil {
			msg := fmt.Errorf("failed to reauthenticate after max session TTL reached: %w", err)
			k.operLock.Unlock()
			return msg
		}
		logger.Info("reauthenticated to vault")
		k.operLock.Unlock()
		return nil
	}
	if expired {
		logger.Info("renewing token")
		renewed, code, err := k.VaultClient.RenewCurrentToken()
		if err != nil {
			if code == 403 {
				err = k.VaultClient.Authenticate()
			}
			k.operLock.Unlock()
			return err
		}
		if renewed {
			logger.Info("renewed session token")
		} else {
			logger.Info("didn't renew token as it was recently renewed")
		}

	}
	k.operLock.Unlock()
	return nil
}

func (k *Kv2Vault) WriteSecret(path string, val map[string]string) error {
	logger := slog.Default()
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.DataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse path %q: %w", escapedPath, err)
		return msg
	}
	guardTime := time.Now().Add(60 * time.Second)
	logger.Debug(
		"checking token against date",
		slog.String("guardDate", guardTime.Format(time.RFC3339)),
	)
	expired := guardTime.After(k.VaultClient.sessionToken.exp)
	if expired {
		k.VaultClient.sessionToken.tokenMutex.Lock()
		expired := guardTime.After(k.VaultClient.sessionToken.exp)
		if expired {
			err = k.checkToken()
			if err != nil {
				msg := fmt.Errorf("token check failed: %w", err)
				k.VaultClient.sessionToken.tokenMutex.Unlock()
				return msg
			}
		}
		time.Sleep(1 * time.Second)
		k.VaultClient.sessionToken.tokenMutex.Unlock()
	}
	k.operLock.RLock()
	req := k.VaultClient.apiClient.NewRequest()
	reqBody := make(map[string]any, 0)
	reqBody["data"] = val
	req.SetBody(reqBody)
	resp, err := req.Post(reqUrl.String())
	k.operLock.RUnlock()
	if err != nil {
		msg := fmt.Errorf("an error occured while writing secret data: %w", err)
		return msg
	}
	if resp.IsError() {
		msg := fmt.Errorf(
			"secret write failed with status '%s' with response body: '%s'",
			resp.Status(),
			string(resp.Body()),
		)
		return msg
	}
	return nil
}

func (k *Kv2Vault) GetSecretMetadata(path string) (*Kv2MetadataResp, error) {
	logger := slog.Default()
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.MetaDataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse request path %q:%w", escapedPath, err)
		return nil, msg
	}
	guardTime := time.Now().Add(60 * time.Second)
	logger.Debug(
		"checking token against date",
		slog.String("guardDate", guardTime.Format(time.RFC3339)),
	)
	expired := guardTime.After(k.VaultClient.sessionToken.exp)
	if expired {
		k.VaultClient.sessionToken.tokenMutex.Lock()
		expired := guardTime.After(k.VaultClient.sessionToken.exp)
		if expired {
			err = k.checkToken()
			if err != nil {
				msg := fmt.Errorf("token check failed: %w", err)
				k.VaultClient.sessionToken.tokenMutex.Unlock()
				return nil, msg
			}
		}
		time.Sleep(1 * time.Second)
		k.VaultClient.sessionToken.tokenMutex.Unlock()
	}
	k.operLock.RLock()
	req := k.VaultClient.apiClient.NewRequest()
	var respBody Kv2MetadataResp
	resp, err := req.Get(reqUrl.String())
	k.operLock.RUnlock()
	if err != nil {
		msg := fmt.Errorf(
			"an error occured while getting metadata for path %q: %w",
			reqUrl.String(),
			err,
		)
		return nil, msg
	}
	if resp.IsError() {
		msg := fmt.Errorf("request failed with status %q", resp.Status())
		return nil, msg
	}
	err = json.Unmarshal(resp.Body(), &respBody)
	if err != nil {
		msg := fmt.Errorf("failed to parse response: %w", err)
		return nil, msg
	}
	return &respBody, nil
}
func (k *Kv2Vault) GetSecretVersion(path string, version int) (*Kv2SecretResp, error) {
	logger := slog.Default()
	escapedPath := escapeRequestPath(path)
	fullPath := fmt.Sprintf("%s?version=%d", escapedPath, version)
	reqUrl, err := k.DataUrl.Parse(fullPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse path %q: %w", fullPath, err)
		return nil, msg
	}
	guardTime := time.Now().Add(60 * time.Second)
	logger.Debug(
		"checking token against date",
		slog.String("guardDate", guardTime.Format(time.RFC3339)),
	)
	expired := guardTime.After(k.VaultClient.sessionToken.exp)
	if expired {
		k.VaultClient.sessionToken.tokenMutex.Lock()
		expired := guardTime.After(k.VaultClient.sessionToken.exp)
		if expired {
			err = k.checkToken()
			if err != nil {
				msg := fmt.Errorf("token check failed: %w", err)
				k.VaultClient.sessionToken.tokenMutex.Unlock()
				return nil, msg
			}
		}
		time.Sleep(1 * time.Second)
		k.VaultClient.sessionToken.tokenMutex.Unlock()
	}
	k.operLock.RLock()
	req := k.VaultClient.apiClient.NewRequest()
	resp, err := req.Get(reqUrl.String())
	k.operLock.RUnlock()
	if err != nil {
		msg := fmt.Errorf("an error occured while reading secret data: %w", err)
		return nil, msg
	}
	if resp.IsError() {
		msg := fmt.Errorf("secret read failed with status %q", resp.Status())
		return nil, msg
	}
	respBody := new(Kv2SecretResp)
	err = json.Unmarshal(resp.Body(), respBody)
	if err != nil {
		msg := fmt.Errorf("failed to parse secret data response: %w", err)
		return nil, msg
	}
	return respBody, nil
}
func (k *Kv2Vault) DeletSecret(path string) error {
	logger := slog.Default()
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.MetaDataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse requested path '%s': %w", escapedPath, err)
		return msg
	}
	guardTime := time.Now().Add(60 * time.Second)
	logger.Debug(
		"checking token against date",
		slog.String("guardDate", guardTime.Format(time.RFC3339)),
	)
	expired := guardTime.After(k.VaultClient.sessionToken.exp)
	if expired {
		k.VaultClient.sessionToken.tokenMutex.Lock()
		expired := guardTime.After(k.VaultClient.sessionToken.exp)
		if expired {
			err = k.checkToken()
			if err != nil {
				msg := fmt.Errorf("token check failed: %w", err)
				k.VaultClient.sessionToken.tokenMutex.Unlock()
				return msg
			}
		}
		time.Sleep(1 * time.Second)
		k.VaultClient.sessionToken.tokenMutex.Unlock()
	}
	k.operLock.RLock()
	req := k.VaultClient.apiClient.NewRequest()
	resp, err := req.Delete(reqUrl.String())
	k.operLock.RUnlock()
	if err != nil {
		msg := fmt.Errorf("an error occured while processing request: %w", err)
		return msg
	}
	if resp.IsError() {
		err := fmt.Errorf("failed to delete secret: '%s'", resp.Status())
		return err
	}
	return nil
}

type Kv2MetadataResp struct {
	Kv2Resp
	Data *Kv2Metadata `json:"data"`
}
type Kv2Metadata struct {
	CasRequired        bool                     `json:"cas_required,omitempty"`
	CreatedTime        string                   `json:"created_time,omitempty"`
	CurrentVersion     int                      `json:"current_version,omitempty"`
	DeleteVersionAfter string                   `json:"delete_version_after,omitempty"`
	MaxVersions        int                      `json:"max_versions,omitempty"`
	OldestVersion      int                      `json:"oldest_version,omitempty"`
	UpdatedTime        string                   `json:"updated_time,omitempty"`
	CustomMetadata     map[string]string        `json:"custom_metadata,omitempty"`
	Versions           map[string]SecretVersion `json:"versions,omitempty"`
}

type Kv2SecretResp struct {
	Kv2Resp
	Data *Kv2SecretData
}

type Kv2SecretData struct {
	Data     map[string]string
	Metadata map[string]any
}
type SecretVersion struct {
	CreatedTime  string `json:"created_time,omitempty"`
	DeletionTime string `json:"deletion_time,omitempty"`
	Destroyed    bool
}

func escapeRequestPath(reqPath string) string {
	path := strings.TrimPrefix(reqPath, "/")
	pathParts := strings.Split(path, "/")
	escapedParts := make([]string, 0)
	for _, v := range pathParts {
		if len(v) == 0 {
			continue
		}
		temp := url.PathEscape(v)
		escapedParts = append(escapedParts, temp)
	}
	escapedPath := strings.Join(escapedParts, "/")
	return escapedPath
}

type Kv2ListResponse struct {
	Kv2Resp
	Data map[string]any
}
