package internal

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type VaultInstance struct {
	BaseURL    string           `mapstructure:"baseUrl"    yaml:"baseUrl"`
	Insecure   bool             `mapstructure:"insecure"   yaml:"insecure"`
	AuthType   string           `mapstructure:"authType"   yaml:"authType"`
	UserCreds  *VaultUserCreds  `mapstructure:"userCreds"  yaml:"userCreds"`
	TokenCreds *VaultTokenCreds `mapstructure:"tokenCreds" yaml:"tokenCreds"`
}

type VaultUserCreds struct {
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}

type VaultTokenCreds struct {
	Token string `mapstructure:"token" yaml:"token"`
}

type ClientConfig struct {
	SrcVault *VaultInstance `mapstructure:"srcVault,omitempty" yaml:"srcVault,omitempty"`
	DstVault *VaultInstance `mapstructure:"dstVault,omitempty" yaml:"dstVault,omitempty"`
	LogLevel string         `mapstructure:"logLevel,omitempty" yaml:"logLevel,omitempty"`
}

func ReadConfig(cfgFile string) {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".vault-cli-go" (without extension).
		viper.AddConfigPath(".")
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".vault-cli")
	}

	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvPrefix("VAULT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetDefault("logLevel", "err")

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	cobra.CheckErr(err)
}
