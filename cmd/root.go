// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/testifysec/witness/cmd/options"

	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/spiffe"

	// imported so their init functions run
	_ "github.com/testifysec/witness/pkg/attestation/commandrun"
	_ "github.com/testifysec/witness/pkg/attestation/environment"
	_ "github.com/testifysec/witness/pkg/attestation/gcp-iit"
	_ "github.com/testifysec/witness/pkg/attestation/git"
	_ "github.com/testifysec/witness/pkg/attestation/gitlab"
	_ "github.com/testifysec/witness/pkg/attestation/jwt"
	_ "github.com/testifysec/witness/pkg/attestation/maven"
	_ "github.com/testifysec/witness/pkg/attestation/oci"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "witness",
		Short:             "Collect and verify attestations about your build environments",
		DisableAutoGenTag: true,
	}
	ro.AddFlags(cmd)
	cmd.AddCommand(SignCmd())
	cmd.AddCommand(VerifyCmd())
	cmd.AddCommand(RunCmd())
	cmd.AddCommand(CompletionCmd())
	cobra.OnInitialize(func() { initConfig(cmd, ro) })
	return cmd
}

func Execute() {
	if err := New().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}

func loadSigner(spiffePath, keyPath, certPath string, intermediatePaths []string) (cryptoutil.Signer, error) {
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
		return nil, fmt.Errorf("failed to open key file: %v", err)
	}

	defer keyFile.Close()
	key, err := cryptoutil.TryParseKeyFromReader(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}

	signerOpts := []cryptoutil.SignerOption{}

	if certPath != "" {
		leaf, err := loadCert(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %v", err)
		}

		signerOpts = append(signerOpts, cryptoutil.SignWithCertificate(leaf))
	}

	if len(intermediatePaths) > 0 {
		intermediates := []*x509.Certificate{}
		for _, path := range intermediatePaths {
			cert, err := loadCert(path)
			if err != nil {
				return nil, fmt.Errorf("failed to load intermediate: %v", err)
			}

			intermediates = append(intermediates, cert)
		}

		signerOpts = append(signerOpts, cryptoutil.SignWithIntermediates(intermediates))
	}

	return cryptoutil.NewSigner(key, signerOpts...)
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

func loadOutfile(outFilePath string) (*os.File, error) {
	var err error
	out := os.Stdout
	if outFilePath != "" {
		out, err = os.Create(outFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %v", err)
		}
	}

	return out, err
}
