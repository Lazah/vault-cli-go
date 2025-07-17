/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/Lazah/vault-cli-go/internal"
	"github.com/spf13/cobra"
)

// moveCmd represents the move command
var moveCmd = &cobra.Command{
	Use:   "move",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		srcMountPath, err := cmd.Flags().GetString("srcMountPath")
		cobra.CheckErr(err)
		dstMountPath, err := cmd.Flags().GetString("dstMountPath")
		cobra.CheckErr(err)
		srcPath, err := cmd.Flags().GetString("srcPath")
		cobra.CheckErr(err)
		dstPath, err := cmd.Flags().GetString("dstPath")
		cobra.CheckErr(err)
		vers, err := cmd.Flags().GetInt("keepVersions")
		cobra.CheckErr(err)

		cmdParams := &internal.CopyParams{
			SrcMountPath: srcMountPath,
			SrcPath:      srcPath,
			DstMountPath: dstMountPath,
			DstPath:      dstPath,
			Versions:     vers,
		}
		internal.MoveSecrets(cmdParams)
	},
}

func init() {
	rootCmd.AddCommand(moveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// moveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// moveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	moveCmd.Flags().String("srcMountPath", "", "Mount path for source KV2 vault")
	moveCmd.Flags().String("srcPath", "", "Root key from which to start copy")
	moveCmd.Flags().
		Int("keepVersions", 1, "How many versions to copy to new path. Default only latest")
	moveCmd.Flags().String("dstMountPath", "", "Mount path for destination KV2 vault")
	moveCmd.Flags().String("dstPath", "", "Root key to where data is copied to")
}
