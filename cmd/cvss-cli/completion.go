package main

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: `Generate a shell completion script for cvss.

To load completions:

Bash:
  $ source <(cvss completion bash)
  # Or add to ~/.bashrc:
  $ cvss completion bash > /etc/bash_completion.d/cvss

Zsh:
  # If shell completion is not already enabled, add to ~/.zshrc:
  autoload -Uz compinit && compinit
  $ cvss completion zsh > "${fpath[1]}/_cvss"

Fish:
  $ cvss completion fish > ~/.config/fish/completions/cvss.fish

PowerShell:
  PS> cvss completion powershell | Out-String | Invoke-Expression
  # Or add to profile:
  PS> cvss completion powershell >> $PROFILE`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			cmd.Root().GenPowerShellCompletion(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
