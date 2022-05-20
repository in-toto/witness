package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/agent/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/testifysec/witness/cmd/witness/cmd"
	"github.com/testifysec/witness/cmd/witness/options"
)

const (
	rekorServer        = "https://log.testifysec.io"
	trust_domain       = "dev.testifysec.com"
	server_address     = "10.24.47.169"
	server_port        = 8081
	SockAddr           = "/tmp/echo.sock"
	insecure_bootstrap = true
)

func main() {

	if err := os.RemoveAll(SockAddr); err != nil {
		fmt.Errorf("here %v", err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		startSpire()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startWitness()
	}()

	wg.Wait()

}

func startSpire() {
	for {
		c, err := spireConfig(SockAddr, server_address, server_port, trust_domain)
		if err != nil {
			fmt.Printf("Spiffee Error: %v\n", err)
			time.Sleep(time.Second * 5)
			continue
		}

		ctx := context.Background()

		err = agent.New(&c).Run(ctx)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			time.Sleep(time.Second * 5)
			continue
		}

	}
}

func startWitness() {
	time.Sleep(time.Second * 2)
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
		Tracing:      false,
	}

	args := []string{"echo", "hello"}

	err := cmd.RunRun(ro, args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

}

func spireConfig(bindAddr string, serverAddr string, serverPort int, trustDomain string) (agent.Config, error) {
	c := agent.Config{}

	serverHostPort := net.JoinHostPort(serverAddr, strconv.Itoa(serverPort))
	c.ServerAddress = fmt.Sprintf("%s", serverHostPort)

	log, err := log.NewLogger()
	if err != nil {
		return c, err
	}

	c.Log = log

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
			"join_token": {},
		},
		"WorkloadAttestor": {
			"unix": {},
		},
	}

	c.TrustDomain = td
	c.BindAddress = bind
	c.InsecureBootstrap = true
	c.DataDir = "."
	c.PluginConfigs = pluginConf
	c.JoinToken = "9b586ac3-115d-45d4-b4a4-bf9993e8683d"

	spew.Dump(c)
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
