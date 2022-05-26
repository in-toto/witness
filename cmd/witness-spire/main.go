package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/spf13/cobra"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/agent/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/testifysec/witness/cmd/witness/cmd"
	"github.com/testifysec/witness/cmd/witness/options"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "witness-spire",
		Short: "Runs witness with the embedded SPIRE agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	return cmd
}

//Defaults
const (
	rekorServer        = "https://log.testifysec.io"
	trustDomain        = "dev.testifysec.io"
	spireServerAddress = "https://spire.testifysec.io"
	spireServerPort    = 443
	trustBundleAddress = "https://bundle.testifysec.io"
	trustBundlePort    = 443
	sockAddr           = "/tmp/echo.sock"
	tpmPath            = "/dev/tpmrm0"

	insecure_bootstrap = true
)

type Options struct {
	RekorServer        string
	TrustDomain        string
	SpireServerAddress string
	SpireServerPort    int
	TrustBundleAddress string
	TrustBundlePort    int
	TPMPath            string
	SockAddr           string //internal socket address
	Log                *log.Logger
}

func (o *Options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.RekorServer, "rekor-server", rekorServer, "Rekor server address")
	cmd.Flags().StringVar(&o.TrustDomain, "trust-domain", trustDomain, "Trust domain")
	cmd.Flags().StringVar(&o.SpireServerAddress, "spire-server-address", spireServerAddress, "Spire server address")
	cmd.Flags().IntVar(&o.SpireServerPort, "spire-server-port", spireServerPort, "Spire server port")
	cmd.Flags().StringVar(&o.TrustBundleAddress, "trust-bundle-address", trustBundleAddress, "Trust bundle address")
	cmd.Flags().IntVar(&o.TrustBundlePort, "trust-bundle-port", trustBundlePort, "Trust bundle port")
	cmd.Flags().StringVar(&o.SockAddr, "sock-addr", sockAddr, "Socket address")
	cmd.Flags().StringVar(&o.TPMPath, "tpm-path", tpmPath, "TPM path")
	logger, err := log.NewLogger()
	if err != nil {
		panic(err)
	}

	o.Log = logger

}

func RunE(cmd *cobra.Command, args []string) error {
	return nil
}

func start(o Options) {
	if err := os.RemoveAll(sockAddr); err != nil {
		fmt.Errorf("here %v", err)
	}

	logger, err := log.NewLogger()
	if err != nil {
		panic(err)
	}

	startSpire(o)

	startWitness(*logger)

}

func startSpire(o Options) {
	go func(o Options) {
		c, err := spireConfig(o.SockAddr, o.SpireServerAddress, o.SpireServerPort, o.TrustDomain, o.Log)
		if err != nil {
			fmt.Printf("Spiffe Error: %v\n", err)
		}

		ctx := context.Background()

		err = agent.New(&c).Run(ctx)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}

	}(o)
}

func startWitness(logger log.Logger) {

	for {

		if _, err := os.Stat("/tmp/echo.sock"); errors.Is(err, os.ErrNotExist) {
		} else {
			break
		}

		time.Sleep(time.Second * 1)
	}

	rootOpt := options.RootOptions{
		Config:   "",
		LogLevel: "debug",
	}

	cmd.RunPreRoot(&rootOpt)

	ro := options.RunOptions{
		KeyOptions: options.KeyOptions{
			KeyPath:           "",
			CertPath:          "",
			IntermediatePaths: nil,
			SpiffePath:        `unix:///tmp/echo.sock`,
			FulcioURL:         "",
			OIDCIssuer:        "",
			OIDCClientID:      "",
		},
		WorkingDir:   ".",
		Attestations: []string{"git", "environment"},
		OutFilePath:  "attestations.json",
		StepName:     "test",
		RekorServer:  rekorServer,
		Tracing:      true,
	}

	args := os.Args[1:]

	err := cmd.RunRun(ro, args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func spireConfig(bindAddr string, serverAddr string, serverPort int, trustDomain string, logger *log.Logger) (agent.Config, error) {
	c := agent.Config{}

	serverHostPort := net.JoinHostPort(serverAddr, strconv.Itoa(serverPort))
	c.ServerAddress = fmt.Sprintf("%s", serverHostPort)

	c.Log = logger

	bind, err := util.GetUnixAddrWithAbsPath(bindAddr)
	if err != nil {
		return c, err
	}

	td, err := common_cli.ParseTrustDomain(trustDomain, nil)
	if err != nil {
		return c, err
	}

	pluginConf := catalog.HCLPluginConfigMap{
		"KeyManager": {
			"disk": {
				PluginData: astPrintf(`directory = "%s"`, "."),
			},
		},
		"NodeAttestor": {
			"tpm": {},
		},
		"WorkloadAttestor": {
			"unix": {},
		},
	}

	c.TrustDomain = td
	c.BindAddress = bind
	c.InsecureBootstrap = insecure_bootstrap
	c.DataDir = "."
	c.PluginConfigs = pluginConf
	return c, nil
}

func astPrintf(format string, args ...interface{}) ast.Node {
	var n ast.Node
	err := hcl.Decode(&n, fmt.Sprintf(format, args...))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}

	return n
}
