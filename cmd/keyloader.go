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
	"fmt"
	"strings"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/file"
	"github.com/in-toto/go-witness/signer/kms"
	"github.com/in-toto/witness/options"
	"github.com/spf13/pflag"
)

// providersFromFlags looks at all flags that were set by the user to determine which providers we should use
func providersFromFlags(prefix string, flags *pflag.FlagSet) map[string]struct{} {
	providers := make(map[string]struct{})
	flags.Visit(func(flag *pflag.Flag) {
		if !strings.HasPrefix(flag.Name, fmt.Sprintf("%s-", prefix)) {
			return
		}

		parts := strings.Split(flag.Name, "-")
		if len(parts) < 2 {
			return
		}

		providers[parts[1]] = struct{}{}
	})

	return providers
}

// loadSigners loads all signers that appear in the signerProviders set and creates their respective signers, using any options provided in so
func loadSigners(ctx context.Context, so options.SignerOptions, ko options.KMSSignerProviderOptions, signerProviders map[string]struct{}) ([]cryptoutil.Signer, error) {
	signers := make([]cryptoutil.Signer, 0)
	for signerProvider := range signerProviders {
		setters := so[signerProvider]
		sp, err := signer.NewSignerProvider(signerProvider, setters...)
		if err != nil {
			log.Errorf("failed to create %v signer provider: %w", signerProvider, err)
			continue
		}

		// NOTE: We want to initialize the KMS provider specific options if a KMS signer has been invoked
		if ksp, ok := sp.(*kms.KMSSignerProvider); ok {
			for _, opt := range ksp.Options {
				for _, setter := range ko[opt.ProviderName()] {
					sp, err = setter(ksp)
					if err != nil {
						continue
					}
				}
			}
		}

		// The file signer provider is activated as soon as any --signer-file-*
		// flag is set, but a certificate, intermediate, or passphrase is useless
		// without a key to pair it with. Left unchecked, this provider silently
		// fails to build below while any other configured signer (e.g. KMS)
		// still succeeds, so the command exits 0 with the certificate quietly
		// dropped instead of surfacing a clear, actionable error.
		if fsp, ok := sp.(file.FileSignerProvider); ok && fsp.KeyPath == "" {
			if fsp.CertPath != "" || len(fsp.IntermediatePaths) > 0 || fsp.PassphrasePath != "" || fsp.Passphrase != nil {
				return nil, fmt.Errorf("--signer-file-key-path is required when other --signer-file-* flags (e.g. --signer-file-cert-path) are set; attaching a file-based certificate to a non-file signer such as KMS is not currently supported")
			}
		}

		s, err := sp.Signer(ctx)
		if err != nil {
			log.Errorf("failed to create %v signer: %w", signerProvider, err)
			continue
		}

		signers = append(signers, s)
	}

	if len(signers) == 0 {
		return signers, fmt.Errorf("failed to load any signers")
	}

	return signers, nil
}

// NOTE: This is a temporary implementation until we have a SignerVerifier interface
// loadVerifiers loads all verifiers that appear in the verifierProviders set and creates their respective verifiers, using any options provided in so
func loadVerifiers(ctx context.Context, so options.VerifierOptions, ko options.KMSVerifierProviderOptions, verifierProviders map[string]struct{}) ([]cryptoutil.Verifier, error) {
	verifiers := make([]cryptoutil.Verifier, 0)
	for verifierProvider := range verifierProviders {
		setters := so[verifierProvider]
		sp, err := signer.NewVerifierProvider(verifierProvider, setters...)
		if err != nil {
			log.Errorf("failed to create %v verifier provider: %w", verifierProvider, err)
			continue
		}

		// NOTE: We want to initialize the KMS provider specific options if a KMS signer has been invoked
		if ksp, ok := sp.(*kms.KMSSignerProvider); ok {
			for _, opt := range ksp.Options {
				pn := opt.ProviderName()
				for _, setter := range ko[pn] {
					vp, err := setter(ksp)
					if err != nil {
						continue
					}

					// NOTE: KMS SignerProvider can also be a VerifierProvider. This is a nasty hack to cast things back in a way that we can add to the loaded verifiers.
					// This must be refactored.
					kspv, ok := vp.(*kms.KMSSignerProvider)
					if !ok {
						return nil, fmt.Errorf("provided verifier provider is not a KMS verifier provider")
					}

					s, err := kspv.Verifier(ctx)
					if err != nil {
						log.Errorf("failed to create %v verifier: %w", verifierProvider, err)
						continue
					}
					verifiers = append(verifiers, s)
				}
			}
		}

		s, err := sp.Verifier(ctx)
		if err != nil {
			log.Errorf("failed to create %v verifier: %w", verifierProvider, err)
			continue
		}

		verifiers = append(verifiers, s)
	}

	return verifiers, nil
}
