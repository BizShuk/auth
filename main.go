// auth is the standalone credential CLI carried by the auth module: the same
// command set (login / list / verify / refresh / logout / use) the aggregated
// auth-cli mounts, with the same default credential directory, so the two
// binaries are interchangeable for credential management.
package main

import (
	"fmt"
	"os"

	"github.com/bizshuk/auth/cmd"
	"github.com/spf13/cobra"
)

const (
	VERSION = "0.1.0"

	// APP_NAME 與 auth-cli 相同,兩個 binary 共用 ~/.config/agentsdk/data/auth。
	APP_NAME = "agentsdk"
)

func main() {
	root := &cobra.Command{
		Use:     "auth",
		Short:   "Log in to LLM providers and manage the stored credentials",
		Version: VERSION,
		// main 負責印錯誤與設定 exit code,cobra 不要再印一次。
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	if err := cmd.Install(root, APP_NAME); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
