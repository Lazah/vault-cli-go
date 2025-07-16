package vault

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

func (k *Kv2Vault) listPath(secretPath string) ([]string, []string, error) {
	escapedSecretPath := escapeRequestPath(secretPath)
	pathUrl, err := k.MetaDataUrl.Parse(escapedSecretPath)
	if err != nil {
		return nil, nil, err
	}
	err = k.CheckToken()
	if err != nil {
		msg := fmt.Errorf("token check failed: %w", err)
		return nil, nil, msg
	}
	req := k.VaultClient.apiClient.NewRequest()
	resp, err := req.Execute("LIST", pathUrl.String())
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
	RequestId     string         `json:"request_id"`
	LeaseId       string         `json:"lease_id"`
	Renewable     bool           `json:"renewable"`
	LeaseDuration int            `json:"lease_duration"`
	WrapInfo      map[string]any `json:"wrap_info"`
	Warnings      map[string]any
	Auth          map[string]any
	MountType     string `json:"mount_type"`
}

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
	return &Kv2Vault{
		VaultClient: c,
		MountPath:   mountPath,
		MetaDataUrl: metadataUrl,
		DataUrl:     dataUrl,
	}, nil
}

func (k *Kv2Vault) GetSecretPaths(startPath string) chan string {
	secretChan := make(chan string, 100)
	go k.getSecretPathsFromPath(startPath, secretChan)
	return secretChan
}

func (k *Kv2Vault) getSecretPathsFromPath(startPath string, respChan chan string) {
	logger := slog.Default()
	defer close(respChan)
	folderChan := make(chan string, 500)
	folderChan <- startPath

	for folder := range folderChan {
		secrets, folders, err := k.listPath(folder)
		if err != nil {
			logger.Error(
				"an error occured while listing path",
				slog.String("path", folder),
				slog.String("error", err.Error()),
			)
		}
		if len(folders) == 0 && len(folderChan) == 0 {
			close(folderChan)
		}
		for _, folder := range folders {
			folderChan <- folder
		}
		for _, secret := range secrets {
			respChan <- secret
		}
	}

}

func (k *Kv2Vault) CheckToken() error {
	guardTime := time.Now().Add(10 * time.Minute)
	expired := k.VaultClient.sessionToken.exp.Before(guardTime)
	var err error
	if expired {
		err = k.VaultClient.RenewCurrentToken()
	}
	if err != nil {
		return err
	}
	return nil
}

func (k *Kv2Vault) WriteSecret(path string, val map[string]string) error {
	req := k.VaultClient.apiClient.NewRequest()
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.DataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse path %q: %w", escapedPath, err)
		return msg
	}
	reqBody := make(map[string]any, 0)
	reqBody["data"] = val
	req.SetBody(reqBody)
	resp, err := req.Post(reqUrl.String())
	if err != nil {
		msg := fmt.Errorf("an error occured while writing secret data: %w", err)
		return msg
	}
	if resp.IsError() {
		msg := fmt.Errorf("secret write failed with status %q", resp.Status())
		return msg
	}
	return nil
}

func (k *Kv2Vault) GetSecretMetadata(path string) (*Kv2MetadataResp, error) {
	req := k.VaultClient.apiClient.NewRequest()
	escapedPath := escapeRequestPath(path)
	reqUrl, err := k.MetaDataUrl.Parse(escapedPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse request path %q:%w", escapedPath, err)
		return nil, msg
	}
	var respBody Kv2MetadataResp
	resp, err := req.Get(reqUrl.String())
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
	req := k.VaultClient.apiClient.NewRequest()
	escapedPath := escapeRequestPath(path)
	fullPath := fmt.Sprintf("%s?version=%d", escapedPath, version)
	reqUrl, err := k.DataUrl.Parse(fullPath)
	if err != nil {
		msg := fmt.Errorf("couldn't parse path %q: %w", fullPath, err)
		return nil, msg
	}
	resp, err := req.Get(reqUrl.String())
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
	req := k.VaultClient.apiClient.NewRequest()
	resp, err := req.Delete(reqUrl.String())
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
	pathParts := strings.Split(reqPath, "/")
	escapedParts := make([]string, 0)
	if len(pathParts) > 0 {
		for _, v := range pathParts {
			if len(v) == 0 {
				continue
			}
			temp := url.PathEscape(v)
			escapedParts = append(escapedParts, temp)
		}
	}
	escapedPath := strings.Join(escapedParts, "/")
	return escapedPath
}

type Kv2ListResponse struct {
	Kv2Resp
	Data map[string]any
}
