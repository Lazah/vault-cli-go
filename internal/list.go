package internal

import (
	"fmt"

	"github.com/Lazah/vault-cli-go/internal/vault"
)

func ListSecrets() {
	client, err := vault.NewClient("http://localhost:8200/")
	if err != nil {
		fmt.Println(err.Error())
	}
	err = client.WithUserAuth("lana", "Password12#", "")
	if err != nil {
		fmt.Println(err.Error())
	}
	err = client.Authenticate()
	if err != nil {
		fmt.Println(err.Error())
	}
	kv2Vault, err := client.NewKv2Vault("secret")
	if err != nil {
		fmt.Println(err.Error())
	}
	secretChan := kv2Vault.GetSecretPaths("")
	paths := make([]string, 0)
	for result := range secretChan {
		paths = append(paths, result)
	}

	fmt.Println("paths:")
	for _, v := range paths {
		fmt.Println(v)
	}

}
