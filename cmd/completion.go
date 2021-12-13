package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script",
	Long: `To load completions:
Bash:
  $ source <(witness completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ witness completion bash > /etc/bash_completion.d/witness
  # macOS:
  $ witness completion bash > /usr/local/etc/bash_completion.d/witness
Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc
  # To load completions for each session, execute once:
  $ witness completion zsh > "${fpath[1]}/_witness"
  # You will need to start a new shell for this setup to take effect.
fish:
  $ witness completion fish | source
  # To load completions for each session, execute once:
  $ witness completion fish > ~/.config/fish/completions/witness.fish
PowerShell:
  PS> witness completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, run:
  PS> witness completion powershell > witness.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			_ = cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			_ = cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			_ = cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			_ = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
