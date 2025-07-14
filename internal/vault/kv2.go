package vault

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func (k *Kv2Vault) listPath(secretPath string) ([]string, []string, error) {
	pathParts := strings.Split(secretPath, "/")
	escapedParts := make([]string, 0)
	if len(pathParts) > 1 {
		for _, v := range pathParts {
			if len(v) == 0 {
				continue
			}
			temp := url.PathEscape(v)
			escapedParts = append(escapedParts, temp)
		}
	}
	escapedSecretPath := strings.Join(escapedParts, "/")
	fullPath := fmt.Sprintf("%s%s", k.MetaDataPath, escapedSecretPath)
	pathUrl, err := k.Client.baseUrl.Parse(fullPath)
	if err != nil {
		return nil, nil, err
	}
	err = k.CheckToken()
	if err != nil {
		msg := fmt.Errorf("token check failed: %w", err)
		return nil, nil, msg
	}
	req := k.Client.client.NewRequest()
	resp, err := req.Execute("LIST", pathUrl.String())
	if err != nil {
		return nil, nil, err
	}
	if resp.IsError() {
		return nil, nil, fmt.Errorf("request failed %s", resp.Status())
	}
	var respBody Kv2Resp
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
	Data          map[string]any `json:"data"`
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
	Client       *VaultClient
	MountPath    string
	MetaDataPath string
	DataPath     string
}

func (c *VaultClient) NewKv2Vault(mountPath string) (*Kv2Vault, error) {
	return &Kv2Vault{
		Client:       c,
		MountPath:    mountPath,
		MetaDataPath: fmt.Sprintf("v1/%s/metadata/", mountPath),
		DataPath:     fmt.Sprintf("v1/%s/data/", mountPath),
	}, nil
}

func (k *Kv2Vault) GetSecretPaths(startPath string) chan string {
	secretChan := make(chan string, 100)
	go k.getSecretPathsFromPath(startPath, secretChan)
	return secretChan
}

func (k *Kv2Vault) getSecretPathsFromPath(startPath string, respChan chan string) {
	defer close(respChan)
	folderChan := make(chan string, 1000)
	folderChan <- startPath

	for folder := range folderChan {
		secrets, folders, err := k.listPath(folder)
		if err != nil {
			fmt.Println("failed to get secrets from path %s" + folder)
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
	exp := k.Client.sessionToken.exp.Before(guardTime)
	var err error
	if exp {
		err = k.Client.RenewCurrentToken()
	}
	if err != nil {
		return err
	}
	return nil
}
