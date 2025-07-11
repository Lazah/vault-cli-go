package vault

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

func (c *VaultClient) ListPath(vaultMountPath, secretPath string) ([]string, []string, error) {
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
	fullPath := fmt.Sprintf("v1/%s/metadata/%s", vaultMountPath, escapedSecretPath)
	pathUrl, err := c.baseUrl.Parse(fullPath)
	if err != nil {
		return nil, nil, err
	}
	req := c.client.NewRequest()
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

func StartPathHandlers(resChan, folderChan chan string, vaultPath string, client *VaultClient, folderGroup *sync.WaitGroup) {
	for range 2 {
		go func() {
			waitCount := 0
		outer:
			for {
				select {
				case folder := <-folderChan:
					secrets, folders, err := client.ListPath(vaultPath, folder)
					if err != nil {
						fmt.Println(err.Error())
					}
					for _, v := range secrets {
						resChan <- v
					}
					for _, v := range folders {
						folderChan <- v
					}
					waitCount = 0
				default:
					if waitCount >= 3 {

						break outer
					}
					time.Sleep(100 * time.Millisecond)
					waitCount++
				}
			}
			folderGroup.Done()
		}()
	}
}
