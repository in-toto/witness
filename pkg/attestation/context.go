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

package attestation

import (
	"context"
	"crypto"
	"fmt"
	"os"

	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/log"
)

type ErrInvalidOption struct {
	Option string
	Reason string
}

type RunType string

const (
	Internal    RunType = "internal"
	PreRunType  RunType = "pre"
	PostRunType RunType = "post"
)

func (r RunType) String() string {
	return string(r)
}

func (e ErrInvalidOption) Error() string {
	return fmt.Sprintf("invalid value for option %v: %v", e.Option, e.Reason)
}

type AttestationContextOption func(ctx *AttestationContext)

func WithContext(ctx context.Context) AttestationContextOption {
	return func(actx *AttestationContext) {
		actx.ctx = ctx
	}
}

func WithHashes(hashes []crypto.Hash) AttestationContextOption {
	return func(ctx *AttestationContext) {
		if len(hashes) > 0 {
			ctx.hashes = hashes
		}
	}
}

func WithWorkingDir(workingDir string) AttestationContextOption {
	return func(ctx *AttestationContext) {
		if workingDir != "" {
			ctx.workingDir = workingDir
		}
	}
}

func WithMaterialAttestor(attestor Attestor) AttestationContextOption {
	return func(ctx *AttestationContext) {
		ctx.materialAttestor = attestor
	}
}

func WithProductAttestor(attestor Attestor) AttestationContextOption {
	return func(ctx *AttestationContext) {
		ctx.productAttestor = attestor
	}
}

func WithCommandAttestor(attestor Attestor) AttestationContextOption {
	return func(ctx *AttestationContext) {
		ctx.commandAttestor = attestor
	}
}

type AttestationContext struct {
	ctx              context.Context
	attestors        []Attestor
	materialAttestor Attestor
	productAttestor  Attestor
	commandAttestor  Attestor
	workingDir       string
	hashes           []crypto.Hash

	completedAttestors []Attestor
	products           map[string]Product
	materials          map[string]cryptoutil.DigestSet
}

type Product struct {
	MimeType string               `json:"mime_type"`
	Digest   cryptoutil.DigestSet `json:"digest"`
}

func NewContext(attestors []Attestor, opts ...AttestationContextOption) (*AttestationContext, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	ctx := &AttestationContext{
		ctx:        context.Background(),
		attestors:  attestors,
		workingDir: wd,
		hashes:     []crypto.Hash{crypto.SHA256},
		materials:  make(map[string]cryptoutil.DigestSet),
		products:   make(map[string]Product),
	}

	for _, opt := range opts {
		opt(ctx)
	}

	return ctx, nil
}

func (ctx *AttestationContext) RunAttestors() error {
	preAttestors := []Attestor{}
	postAttestors := []Attestor{}

	for _, attestor := range ctx.attestors {
		switch attestor.RunType() {
		case PreRunType:
			preAttestors = append(preAttestors, attestor)

		case PostRunType:
			postAttestors = append(postAttestors, attestor)

		case Internal:
			if attestor.Name() == "material" {
				ctx.materialAttestor = attestor
			}

			if attestor.Name() == "product" {
				ctx.productAttestor = attestor
			}

		default:
			return ErrInvalidOption{
				Option: "attestor.RunType",
				Reason: fmt.Sprintf("unknown run type %v", attestor.RunType()),
			}
		}
	}

	for _, attestor := range preAttestors {
		if err := ctx.runAttestor(attestor); err != nil {
			return err
		}
	}

	if ctx.materialAttestor != nil {
		if err := ctx.runAttestor(ctx.materialAttestor); err != nil {
			return err
		}
	}

	if ctx.commandAttestor != nil {
		if err := ctx.runAttestor(ctx.commandAttestor); err != nil {
			return err
		}
	}

	if ctx.productAttestor != nil {
		if err := ctx.runAttestor(ctx.productAttestor); err != nil {
			return err
		}
	}

	for _, attestor := range postAttestors {
		if err := ctx.runAttestor(attestor); err != nil {
			return err
		}
	}

	return nil
}

func (ctx *AttestationContext) runAttestor(attestor Attestor) error {
	log.Infof("Starting %v attestor...", attestor.Name())
	if err := attestor.Attest(ctx); err != nil {
		return err
	}

	ctx.completedAttestors = append(ctx.completedAttestors, attestor)
	if materialer, ok := attestor.(Materialer); ok {
		ctx.addMaterials(materialer)
	}

	if producter, ok := attestor.(Producer); ok {
		ctx.addProducts(producter)
	}

	return nil
}

func (ctx *AttestationContext) CompletedAttestors() []Attestor {
	attestors := make([]Attestor, len(ctx.completedAttestors))
	copy(attestors, ctx.completedAttestors)
	return attestors
}

func (ctx *AttestationContext) WorkingDir() string {
	return ctx.workingDir
}

func (ctx *AttestationContext) Hashes() []crypto.Hash {
	hashes := make([]crypto.Hash, len(ctx.hashes))
	copy(hashes, ctx.hashes)
	return hashes
}

func (ctx *AttestationContext) Context() context.Context {
	return ctx.ctx
}

func (ctx *AttestationContext) Materials() map[string]cryptoutil.DigestSet {
	matCopy := make(map[string]cryptoutil.DigestSet)
	for k, v := range ctx.materials {
		matCopy[k] = v
	}

	return matCopy
}

func (ctx *AttestationContext) Products() map[string]Product {
	prodCopy := make(map[string]Product)
	for k, v := range ctx.products {
		prodCopy[k] = v
	}

	return ctx.products
}

func (ctx *AttestationContext) addMaterials(materialer Materialer) {
	newMats := materialer.Materials()
	for k, v := range newMats {
		ctx.materials[k] = v
	}
}

func (ctx *AttestationContext) addProducts(producter Producer) {
	newProds := producter.Products()
	for k, v := range newProds {
		ctx.products[k] = v
	}
}
