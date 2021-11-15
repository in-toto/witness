package attestation

import (
	"strings"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/run"
)

const (
	CommandRunName = "CommandRun"
	CommandRunURI  = "https://witness.testifysec.com/attestations/CommandRun/v0.1"
)

func init() {
	RegisterAttestation(CommandRunName, CommandRunURI, NewCommandRun)
}

func NewCommandRun() Attestor {
	return &CommandRun{}
}

type Environment struct {
	OS        string            `json:"os,omitempty"`
	Hostname  string            `json:"hostname,omitempty"`
	Username  string            `json:"username,omitempty"`
	Variables map[string]string `json:"variables,omitempty"`
}

type Command struct {
	Cmd      string               `json:"cmd"`
	Args     []string             `json:"args"`
	Stdout   string               `json:"stdout,omitempty"`
	Stderr   string               `json:"stderr,omitempty"`
	ExitCode int                  `json:"exitcode"`
	Products map[string]DigestMap `json:"products"`
}

type CommandRun struct {
	Environment Environment          `json:"environment"`
	Materials   map[string]DigestMap `json:"materials,omitempty"`
	Commands    []Command
}

type DigestMap map[string]string

func transformRunArtifacts(runArtifacts map[string]run.Artifact) map[string]DigestMap {
	artifacts := make(map[string]DigestMap)
	for path, runArtifact := range runArtifacts {
		digestMap := make(DigestMap)
		for hash, digest := range runArtifact.Digests {
			digestMap[strings.ToLower(strings.ReplaceAll(hash.String(), "-", ""))] = string(crypto.HexEncode(digest))
		}

		artifacts[path] = digestMap
	}

	return artifacts
}

func (rc *CommandRun) Attest(result run.Result) error {
	newRc := CommandRun{
		Environment: Environment{
			OS:        result.Environment.OS,
			Hostname:  result.Environment.Hostname,
			Username:  result.Environment.Username,
			Variables: result.Environment.Variables,
		},
		Materials: transformRunArtifacts(result.Artifacts),
		Commands:  make([]Command, 0),
	}

	for _, command := range result.CommandResults {
		cmd := Command{
			Cmd:      command.Cmd,
			Args:     command.Args,
			Stdout:   string(command.Stdout),
			Stderr:   string(command.Stderr),
			ExitCode: command.ExitCode,
			Products: transformRunArtifacts(command.Artifacts),
		}

		newRc.Commands = append(newRc.Commands, cmd)
	}

	*rc = newRc
	return nil
}

func (rc *CommandRun) Name() string {
	return CommandRunName
}

func (rc *CommandRun) URI() string {
	return CommandRunURI
}

func (rc *CommandRun) Subjects() map[string]DigestMap {
	allProducts := make(map[string]DigestMap)
	for _, cmd := range rc.Commands {
		for prod, digest := range cmd.Products {
			allProducts[prod] = digest
		}
	}

	return allProducts
}
