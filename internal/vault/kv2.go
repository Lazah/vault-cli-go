package vault

import (
	"fmt"
)

func (c *VaultClient) ListPath(vaultMountPath, secretPath string) ([]string, error) {
	fullPath := fmt.Sprintf("%s/metadata/%s", vaultMountPath, secretPath)
	pathUrl, err := c.baseUrl.Parse(fullPath)
	if err != nil {
		return nil, err
	}
	return nil, nil
}
