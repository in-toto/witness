package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/spiffe/spire/cmd/spire-agent/cli"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/agent/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/util"
)

const (
	rekorServer        = "https://log.testifyse.io"
	trust_domain       = "dev.testifysec.com"
	server_address     = "10.24.47.169"
	server_port        = 8081
	sockAddr           = "/tmp/spire.sock"
	insecure_bootstrap = true
)

func main() {

	if err := os.RemoveAll(sockAddr); err != nil {
		fmt.Errorf("%v", err)
	}

	new(cli.CLI).Run(os.Args)

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
		c, err := spireConfig(sockAddr, server_address, server_port, trust_domain)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
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
			"memory": {},
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
	c.JoinToken = "e2e97430-9245-426f-968e-d836e681239c"
	return c, nil
}
