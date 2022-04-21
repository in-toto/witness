## witness completion

Generate completion script

### Synopsis

To load completions:
bash:
  $ source <(witness completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ witness completion bash > /etc/bash_completion.d/witness
  # macOS:
  $ witness completion bash > /usr/local/etc/bash_completion.d/witness
zsh:
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


```
witness completion [bash|zsh|fish|powershell]
```

### Options

```
  -h, --help   help for completion
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments

