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

	"github.com/in-toto/witness/options"
	"github.com/spf13/pflag"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/signer"
)

// signerProvidersFromFlags looks at all flags that were set by the user to determine which signer providers we should use
func signerProvidersFromFlags(flags *pflag.FlagSet) map[string]struct{} {
	signerProviders := make(map[string]struct{})
	flags.Visit(func(flag *pflag.Flag) {
		if !strings.HasPrefix(flag.Name, "signer-") {
			return
		}

		parts := strings.Split(flag.Name, "-")
		if len(parts) < 2 {
			return
		}

		signerProviders[parts[1]] = struct{}{}
	})

	return signerProviders
}

// loadSigners loads all signers that appear in the signerProviders set and creates their respective signers, using any options provided in so
func loadSigners(ctx context.Context, so options.SignerOptions, signerProviders map[string]struct{}) ([]cryptoutil.Signer, error) {
	signers := make([]cryptoutil.Signer, 0)
	for signerProvider := range signerProviders {
		setters := so[signerProvider]
		sp, err := signer.NewSignerProvider(signerProvider, setters...)
		if err != nil {
			log.Errorf("failed to create %v signer provider: %w", signerProvider, err)
			continue
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
