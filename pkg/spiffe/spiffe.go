// Copyright 2021 The TestifySec Authors
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

package spiffe

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

type ErrInvalidSVID string

func (e ErrInvalidSVID) Error() string {
	return fmt.Sprintf("invalid svid: %v", string(e))
}

func Signer(ctx context.Context, socketPath string) (*cryptoutil.X509Signer, error) {
	svidCtx, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return nil, err
	}

	svid := svidCtx.DefaultSVID()
	if len(svid.Certificates) <= 0 {
		return nil, ErrInvalidSVID("no certificates")
	}

	if svid.PrivateKey == nil {
		return nil, ErrInvalidSVID("no private key")
	}

	return cryptoutil.NewX509Signer(svid.PrivateKey, svid.Certificates[0], svid.Certificates[1:], nil)
}
