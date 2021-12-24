package cmd

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/spiffe"

	// imported so their init functions run
	_ "github.com/testifysec/witness/pkg/attestation/artifact"
	_ "github.com/testifysec/witness/pkg/attestation/commandrun"
	_ "github.com/testifysec/witness/pkg/attestation/environment"
	_ "github.com/testifysec/witness/pkg/attestation/gcp-iit"
	_ "github.com/testifysec/witness/pkg/attestation/git"
	_ "github.com/testifysec/witness/pkg/attestation/gitlab"
	_ "github.com/testifysec/witness/pkg/attestation/jwt"
)

var keyPath string
var certPath string
var intermediatePaths []string
var spiffePath string
var config string
var cpuprofile string
var cpuprofilefile *os.File

var rootCmd = &cobra.Command{
	Use:                "witness",
	Short:              "Collect and verify attestations about your build environments",
	PersistentPreRunE:  rootPreRun,
	PersistentPostRunE: rootPostRun,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&config, "config", "c", ".witness.yaml", "Path to the witness config file")
	rootCmd.PersistentFlags().StringVar(&cpuprofile, "cpuprofile", "", "Path to store the cpu profile information")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}

func rootPreRun(cmd *cobra.Command, args []string) error {
	if cpuprofile == "" {
		return nil
	}

	var err error
	cpuprofilefile, err = os.Create(cpuprofile)
	if err != nil {
		return err
	}

	if err := pprof.StartCPUProfile(cpuprofilefile); err != nil {
		return err
	}

	return nil
}

func rootPostRun(cmd *cobra.Command, args []string) error {
	if cpuprofile == "" {
		return nil
	}

	pprof.StopCPUProfile()
	if err := cpuprofilefile.Close(); err != nil {
		return err
	}

	return nil
}

func GetCommand() *cobra.Command {
	return rootCmd
}

func addKeyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to the signing key")
	cmd.Flags().StringVar(&certPath, "certificate", "", "Path to the signing key's certificate")
	cmd.Flags().StringSliceVarP(&intermediatePaths, "intermediates", "i", []string{}, "Intermediates that link trust back to a root in the policy")
	cmd.Flags().StringVar(&spiffePath, "spiffe-socket", "", "Path to the SPIFFE Workload API socket")
}

func loadSigner() (cryptoutil.Signer, error) {
	if spiffePath == "" && keyPath == "" {
		return nil, fmt.Errorf("one of key or spiffe-socket flags must be provided")
	} else if spiffePath != "" && keyPath != "" {
		return nil, fmt.Errorf("only one of key or spiffe-socket flags may be provided")
	}

	if spiffePath != "" {
		return spiffe.Signer(context.Background(), spiffePath)
	}

	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not open key file: %v", err)
	}

	defer keyFile.Close()
	key, err := cryptoutil.TryParseKeyFromReader(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}

	if certPath == "" {
		return cryptoutil.NewSigner(key)
	}

	leaf, err := loadCert(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	intermediates := []*x509.Certificate{}
	for _, path := range intermediatePaths {
		cert, err := loadCert(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load intermediate: %v", err)
		}

		intermediates = append(intermediates, cert)
	}

	return cryptoutil.NewX509Signer(key, leaf, intermediates, nil)
}

func loadCert(path string) (*x509.Certificate, error) {
	certFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	defer certFile.Close()
	possibleCert, err := cryptoutil.TryParseKeyFromReader(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate")
	}

	cert, ok := possibleCert.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("%v is not a x509 certificate", path)
	}

	return cert, nil
}

func loadOutfile() (*os.File, error) {
	var err error
	out := os.Stdout
	if outFilePath != "" {
		out, err = os.Create(outFilePath)
		if err != nil {
			return nil, fmt.Errorf("could not create output file: %v", err)
		}
	}

	return out, err
}
