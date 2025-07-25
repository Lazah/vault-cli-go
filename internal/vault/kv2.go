package vault

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
)

func (k *Kv2Vault) ListPath(secretPath string) ([]string, []string, error) {
	escapedSecretPath := escapeRequestPath(secretPath)
	pathUrl, err := k.MetaDataUrl.Parse(escapedSecretPath)
	if err != nil {
		return nil, nil, err
	}
	k.checkToken()
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

func (k *Kv2Vault) checkToken() error {
	vault := fmt.Sprintf("%s/%s", k.VaultClient.baseUrl.String(), k.MountPath)
	logger := slog.Default().With("vault", vault)
	k.operLock.Lock()
	logger.Debug("checking if token needs to be renewed")
	refreshed, err := k.VaultClient.RenewCurrentToken()
	if err != nil {
		logger.Error("token renew failed")
		k.operLock.Unlock()
		return err
	}
	if refreshed {
		logger.Debug("renewed token")
	} else {
		logger.Debug("didn't renew token")
	}

	k.operLock.Unlock()
	return nil
}

func (k *Kv2Vault) WriteSecret(path string, val map[string]string) error {
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.DataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse path %q: %w", escapedPath, err)
		return msg
	}
	k.checkToken()
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
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.MetaDataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse request path %q:%w", escapedPath, err)
		return nil, msg
	}
	k.checkToken()
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
	escapedPath := escapeRequestPath(path)
	fullPath := fmt.Sprintf("%s?version=%d", escapedPath, version)
	reqUrl, err := k.DataUrl.Parse(fullPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse path %q: %w", fullPath, err)
		return nil, msg
	}
	k.checkToken()
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
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.MetaDataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse requested path '%s': %w", escapedPath, err)
		return msg
	}
	k.checkToken()
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
