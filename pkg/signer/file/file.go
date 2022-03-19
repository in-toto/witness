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

package file

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/testifysec/witness/pkg/cryptoutil"
)

func GetSigner(ctx context.Context, keyPath, certPath string, intermediatePaths []string) (cryptoutil.Signer, error) {
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
