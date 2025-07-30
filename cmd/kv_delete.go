/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/Lazah/vault-cli-go/internal"
	"github.com/spf13/cobra"
)

// kvDeleteCmd represents the delete command
var kvDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		mountPath, err := cmd.Flags().GetString("srcMountPath")
		cobra.CheckErr(err)
		path, err := cmd.Flags().GetString("srcPath")
		cobra.CheckErr(err)
		deleteParams := &internal.DeleteParams{
			SrcMountPath: mountPath,
			SrcPath:      path,
		}
		internal.DeleteSecrets(*deleteParams)
	},
}

func init() {
	kvCmd.AddCommand(kvDeleteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deleteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deleteCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	kvDeleteCmd.Flags().String("srcMountPath", "", "Mount path for source KV2 vault")
	kvDeleteCmd.Flags().String("srcPath", "", "Root key from which to start copy")
}
