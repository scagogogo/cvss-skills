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
		var err error
		switch args[0] {
		case "bash":
			err = cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			err = cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			err = cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			err = cmd.Root().GenPowerShellCompletion(os.Stdout)
		}
		if err != nil {
			dief("Completion generation error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}