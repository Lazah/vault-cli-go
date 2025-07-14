package internal

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/Lazah/vault-cli-go/internal/vault"
	"github.com/spf13/viper"
)

func ListSecrets() {
	logger := slog.Default()
	var cfg ClientConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		logger.Error("an error occured while reading config", slog.String("error", err.Error()))
		os.Exit(10)
	}
	if cfg.SrcVault == nil {
		logger.Error("source vault info missing... terminating")
		os.Exit(10)
	}
	client, err := vault.NewClient(cfg.SrcVault.BaseURL)
	if err != nil {
		fmt.Println(err.Error())
	}
	err = client.WithUserAuth(cfg.SrcVault.UserCreds.Username, cfg.SrcVault.UserCreds.Password, "")
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
