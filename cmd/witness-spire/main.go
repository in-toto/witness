package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/agent/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/testifysec/witness/cmd"
	"github.com/testifysec/witness/options"
)

//Defaults
const (
	rekorServer        = "https://log.testifysec.io"
	trustDomain        = "dev.testifysec.com"
	spireServerAddress = "spire.testifysec.io"
	spireServerPort    = 443
	trustBundleAddress = "https://bundle.testifysec.io/"
	logLevel           = "debug"
)

type Conf struct {
	RekorServer        string
	TrustDomain        string
	SpireServerAddress string
	SpireServerPort    int
	TrustBundleURL     string
	TPMPath            string
	SockAddr           string //internal socket address
	LogLevel           string
	Log                *log.Logger
	Args               []string
	Trace              bool
	Attestors          []string
	StepName           string
	NodeAttestor       string
}

func (o *Conf) DetectStepName() {
	//check to see if we have a step name from a flag
	if o.StepName != "" {
		return
	}

	//check to see if we have a step name from an env variable
	if os.Getenv("WITNESS_STEP_NAME") != "" {
		o.StepName = os.Getenv("WITNESS_STEP_NAME")
		return
	}

	//check to see if we have a step name from a GitLab CI env variable
	if os.Getenv("CI_JOB_STAGE") != "" {
		o.StepName = os.Getenv("CI_JOB_STAGE")
		o.Attestors = append(o.Attestors, "gitlab")
		return
	}

	//check to see if we have a step name from a GitHub Actions env variable
	if os.Getenv("GITHUB_JOB") != "" {
		o.StepName = os.Getenv("GITHUB_JOB")
		return
	}

	//check to see if we have a step name from a Jenkins env variable
	if os.Getenv("STAGE_NAME") != "" {
		o.StepName = os.Getenv("STAGE_NAME")
		return
	}

	//check to see if we have a step name from a CircleCI env variable
	if os.Getenv("CIRCLE_JOB") != "" {
		o.StepName = os.Getenv("CIRCLE_JOB")
		return
	}

	//check to see if we have a step name from a GOCD env variable
	if os.Getenv("GO_STAGE_NAME") != "" {
		o.StepName = os.Getenv("GO_STAGE_NAME")
		return
	}

	//check to see if we have a step name from a Drone env variable
	if os.Getenv("DRONE_STEP_NAME") != "" {
		o.StepName = os.Getenv("DRONE_STEP_NAME")
		return
	}

	if o.StepName == "" {
		o.Log.Errorf("No step name found. Please set the WITNESS_STEP_NAME environment variable or use the --step-name flag")
		os.Exit(1)
	}


}

func (o *Conf) DetectCloudEnv() {
	if o.NodeAttestor != "tpm" {
		//Check to see if we are running on GCP
		if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" {
			o.Log.Infof("Detected GCP environment")
			o.Attestors = append(o.Attestors, "gcp_iit")
			o.NodeAttestor = "gcp_iit"
			return
		}

		//Check to see if we are running on AWS
		if os.Getenv("AWS_REGION") != "" {
			o.Log.Infof("Detected AWS environment")
			o.Attestors = append(o.Attestors, "aws_iid")
			o.NodeAttestor = "aws_iid"
			return
		}
	} else {

		//Check to see if we have a tpm path
		if o.TPMPath == "" {
			o.TPMPath = "/dev/tpmrm0"
		}

		info, err := os.Stat(o.TPMPath)
		if err != nil {
			o.Log.Errorf("Error getting TPM info: %v", err)
		}

		//Default to using the TPM if we find it
		if info.Mode()&os.ModeDevice != 0 {
			o.Log.Infof("Detected TPM device")
			o.NodeAttestor = "tpm"
			return
		} else {
			o.Log.Infof("No Identity Devices or Services Found - Make sure permissions are set correctly on the TPM device see README")
			o.Log.Infof("If you are using a TPM device, make sure the device is not in use by another process")
			
		}
	}

}

func (o *Conf) AddFlags(cmd *cobra.Command) {
	sockAddr := filepath.Join(os.TempDir(), "witness-spire.sock")

	cmd.Flags().StringVar(&o.RekorServer, "rekor-server", rekorServer, "rekor server address")
	cmd.Flags().StringVar(&o.TrustDomain, "trust-domain", trustDomain, "trust domain")
	cmd.Flags().StringVar(&o.SpireServerAddress, "spire-server-address", spireServerAddress, "ppire server address")
	cmd.Flags().IntVar(&o.SpireServerPort, "spire-server-port", spireServerPort, "spire server port")
	cmd.Flags().StringVar(&o.TrustBundleURL, "trust-bundle-url", trustBundleAddress, "trust bundle address")
	cmd.Flags().StringVar(&o.SockAddr, "sock-addr", sockAddr, "socket address")
	cmd.Flags().StringVar(&o.LogLevel, "log-level", logLevel, "log level")
	cmd.Flags().BoolVar(&o.Trace, "trace", false, "trace")
	cmd.Flags().StringSliceVar(&o.Attestors, "attestors", []string{}, "attestors")
	cmd.Flags().StringVar(&o.StepName, "step-name", "", "step name")
	cmd.Flags().StringVar(&o.NodeAttestor, "node-attestor", "tpm", "node attestor")

	logLevel := log.WithLevel(o.LogLevel)
	logger, err := log.NewLogger(logLevel)
	if err != nil {
		panic(err)
	}
	o.Log = logger

}

func main() {
	cmd := New()
	RunE(cmd, os.Args[1:])

}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "witness-spire",
		Short: "Runs witness with the embedded SPIRE agent",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			RunE(cmd, args)
			return nil

		},
	}
	return cmd

}

func RunE(cmd *cobra.Command, args []string) {
	newArgs := []string{}

	for i, arg := range args {
		//if we have "--" then execute everything after that
		if arg == "--" {
			newArgs = args[i+1:]
			break
		}
		if strings.Contains(arg, "--") {
			continue
		} else {
			newArgs = append(newArgs, arg)
		}
	}

	o := Conf{}
	o.AddFlags(cmd)

	//Parse flags
	if err := cmd.ParseFlags(args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	o.DetectStepName()
	o.DetectCloudEnv()
	o.Args = newArgs

	start(o)
}

func start(o Conf) {

	startSpire(o)
	startWitness(o)

}

func startSpire(o Conf) {
	go func(o Conf) {
		c, err := spireConfig(o)
		if err != nil {
			fmt.Printf("Spiffe Error: %v\n", err)
			os.Exit(1)
		}

		ctx := context.Background()
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second*30))
		defer cancel()

		err = agent.New(&c).Run(ctx)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	}(o)
}

func startWitness(o Conf) {
	//figure out what environmnet we are in
	//TPM - AWS - GCP - Azure - etc
	//What CI System are we in? - CircleCI - TravisCI - GitlabCI - etc
	//Try popular environment variables for step name
	//Check to see if we are in interactive mode

	for {

		if _, err := os.Stat(o.SockAddr); errors.Is(err, os.ErrNotExist) {
		} else {
			break
		}

	}

	for {

		_, err := net.Dial("unix", o.SockAddr)
		if err != nil {
		} else {
			break
		}
	}

	o.SockAddr = "unix://" + o.SockAddr

	rootOpt := options.RootOptions{
		Config:   "",
		LogLevel: o.LogLevel,
	}

	err := cmd.RunPreRoot(&rootOpt)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	ro := options.RunOptions{
		KeyOptions: options.KeyOptions{
			KeyPath:           "",
			CertPath:          "",
			IntermediatePaths: nil,
			SpiffePath:        o.SockAddr,
			FulcioURL:         "",
			OIDCIssuer:        "",
			OIDCClientID:      "",
		},
		WorkingDir:   ".",
		Attestations: o.Attestors,
		OutFilePath:  "attestations.json",
		StepName:     o.StepName,
		RekorServer:  o.RekorServer,
		Tracing:      o.Trace,
	}

	err = cmd.RunRun(ro, o.Args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func spireConfig(o Conf) (agent.Config, error) {
	c := agent.Config{}

	bundle, err := downloadTrustBundle(o.TrustBundleURL)
	if err != nil {
		return c, err
	}

	c.TrustBundle = bundle

	dataDir := filepath.Join(os.TempDir(), "spire")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		{
			return agent.Config{}, fmt.Errorf("error creating spire data directory: %v", err)
		}
	}
	c.DataDir = dataDir
	c.ServerAddress = net.JoinHostPort(o.SpireServerAddress, strconv.Itoa(o.SpireServerPort))

	l, err := log.NewLogger()
	if err != nil {
		return agent.Config{}, fmt.Errorf("error creating spire logger: %v", err)
	}
	c.Log = l

	bind, err := util.GetUnixAddrWithAbsPath(o.SockAddr)
	if err != nil {
		return c, err
	}

	c.BindAddress = bind

	o.Log.Debugf("Binding to socket %s", bind)

	td, err := common_cli.ParseTrustDomain(trustDomain, nil)
	if err != nil {
		return c, err
	}

	c.TrustDomain = td

	pluginConf := o.getPluginConfig()
	c.PluginConfigs = pluginConf
	c.InsecureBootstrap = false

	return c, nil
}

func downloadTrustBundle(trustBundleURL string) ([]*x509.Certificate, error) {
	// Download the trust bundle URL from the user specified URL
	// We use gosec -- the annotation below will disable a security check that URLs are not tainted
	/* #nosec G107 */
	resp, err := http.Get(trustBundleURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch trust bundle URL %s: %w", trustBundleURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error downloading trust bundle: %s", resp.Status)
	}
	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read from trust bundle URL %s: %w", trustBundleURL, err)
	}

	bundle, err := pemutil.ParseCertificates(pemBytes)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func (o Conf) getPluginConfig() catalog.HCLPluginConfigMap {
	pluginConf := catalog.HCLPluginConfigMap{
		"KeyManager": {
			"memory": {},
		},
		"NodeAttestor": {
			o.NodeAttestor: {},
		},
		"WorkloadAttestor": {
			"unix":   {},
			"docker": {},
		},
	}

	return pluginConf
}

// astPrint impliments the ast.Visitor interface needed for creating the options struct for the spire agent
// func astPrintf(format string, args ...interface{}) ast.Node {
// 	var n ast.Node
// 	err := hcl.Decode(&n, fmt.Sprintf(format, args...))
// 	if err != nil {
// 		fmt.Printf("Error: %v\n", err)
// 		panic(err)
// 	}

// 	return n
// }
