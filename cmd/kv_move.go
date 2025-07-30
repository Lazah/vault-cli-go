/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/Lazah/vault-cli-go/internal"
	"github.com/spf13/cobra"
)

// kvMoveCmd represents the move command
var kvMoveCmd = &cobra.Command{
	Use:   "move",
	Short: "Moves secrets between KV vaults or within the same vault",
	Long:  ``,
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
		filterPaths, err := cmd.Flags().GetBool("filterPaths")
		cobra.CheckErr(err)
		filterExp, err := cmd.Flags().GetString("filterExp")
		cobra.CheckErr(err)
		modDstPaths, err := cmd.Flags().GetBool("renameDst")
		cobra.CheckErr(err)
		srcPart, err := cmd.Flags().GetString("oldPart")
		cobra.CheckErr(err)
		dstPart, err := cmd.Flags().GetString("newPart")
		cobra.CheckErr(err)

		cmdParams := &internal.KvParams{
			SrcMountPath: srcMountPath,
			SrcPath:      srcPath,
			DstMountPath: dstMountPath,
			DstPath:      dstPath,
			Versions:     vers,
			FilterPaths:  filterPaths,
			FilterExpStr: filterExp,
			ModDstPaths:  modDstPaths,
			OldPathPart:  srcPart,
			NewPathPart:  dstPart,
		}
		internal.MoveSecrets(cmdParams)
	},
}

func init() {
	kvCmd.AddCommand(kvMoveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// moveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// moveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	kvMoveCmd.Flags().String("srcMountPath", "", "Mount path for source KV2 vault")
	kvMoveCmd.Flags().String("srcPath", "", "Root key from which to start copy")
	kvMoveCmd.Flags().
		Int("keepVersions", -1, "How many versions to copy to new path. Default to '-1' to keep all versions")
	kvMoveCmd.Flags().String("dstMountPath", "", "Mount path for destination KV2 vault")
	kvMoveCmd.Flags().String("dstPath", "", "Root key to where data is copied to")
	kvMoveCmd.Flags().Bool("filterPaths", false, "Determines if source paths should be filtered")
	kvMoveCmd.Flags().String("filterExp", "", "Source path filter as go regexp")
	kvMoveCmd.MarkFlagsRequiredTogether("filterPaths", "filterExp")
	kvMoveCmd.Flags().
		Bool("renameDst", false, "Determines if destination paths should be manipulated")
	kvMoveCmd.Flags().String("oldPart", "", "What should be replaced from destination path")
	kvMoveCmd.Flags().String("newPart", "", "New path part")
	kvMoveCmd.MarkFlagsRequiredTogether("renameDst", "oldPart", "newPart")
}
