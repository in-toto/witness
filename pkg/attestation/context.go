// Copyright 2021 The Witness Contributors
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
)

type ErrInvalidOption struct {
	Option string
	Reason string
}

type ErrInternal struct {
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

func (e ErrInternal) Error() string {
	return fmt.Sprintf("internal error: %v", e.Reason)
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

type AttestationContext struct {
	ctx                context.Context
	attestors          []Attestor
	workingDir         string
	hashes             []crypto.Hash
	completedAttestors []Attestor
	stepName           string
	Products           map[string]cryptoutil.DigestSet
}

type Product struct {
	MimeType string               `json:"mime_type"`
	Digest   cryptoutil.DigestSet `json:"digest"`
}

func NewContext(stepName string, attestors []Attestor, opts ...AttestationContextOption) (*AttestationContext, error) {
	if len(attestors) <= 0 {
		return nil, ErrInvalidOption{
			Option: "attestors",
			Reason: "at least one attestor required",
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	ctx := &AttestationContext{
		ctx:        context.Background(),
		attestors:  attestors,
		workingDir: wd,
		hashes:     []crypto.Hash{crypto.SHA256},
		stepName:   stepName,
	}

	for _, opt := range opts {
		opt(ctx)
	}

	return ctx, nil
}

func (ctx *AttestationContext) RunAttestors() error {
	preAttestors := []Attestor{}
	postAttestors := []Attestor{}
	var cmdAttestor Attestor
	var materialAttestor Attestor
	var productAttestor Attestor

	for _, attestor := range ctx.attestors {

		switch attestor.RunType() {
		case PreRunType:
			preAttestors = append(preAttestors, attestor)

		case Internal:
			if attestor.Name() == "command-run" {
				cmdAttestor = attestor
			}
			if attestor.Name() == "material" {
				materialAttestor = attestor
			}
			if attestor.Name() == "product" {
				productAttestor = attestor
			}

		case PostRunType:
			postAttestors = append(postAttestors, attestor)

		default:
			return ErrInvalidOption{
				Option: "attestor.RunType",
				Reason: fmt.Sprintf("unknown run type %v", attestor.RunType()),
			}
		}
	}

	if materialAttestor == nil || productAttestor == nil || cmdAttestor == nil {
		return ErrInternal{
			Reason: "missing required attestors",
		}
	}

	for _, attestor := range preAttestors {
		if err := attestor.Attest(ctx); err != nil {
			return err
		}
		ctx.completedAttestors = append(ctx.completedAttestors, attestor)
	}

	if err := materialAttestor.Attest(ctx); err != nil {
		return err
	}
	ctx.completedAttestors = append(ctx.completedAttestors, materialAttestor)

	if err := cmdAttestor.Attest(ctx); err != nil {
		return err
	}
	ctx.completedAttestors = append(ctx.completedAttestors, cmdAttestor)

	if err := productAttestor.Attest(ctx); err != nil {
		return err
	}
	ctx.completedAttestors = append(ctx.completedAttestors, productAttestor)

	for _, attestor := range postAttestors {
		if err := attestor.Attest(ctx); err != nil {
			return err
		}
		ctx.completedAttestors = append(ctx.completedAttestors, attestor)
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

func (ctx *AttestationContext) GetMaterials() (map[string]cryptoutil.DigestSet, error) {
	allMaterials := make(map[string]cryptoutil.DigestSet)

	for _, attestor := range ctx.attestors {
		materialer, ok := attestor.(Materialer)
		if !ok {
			continue
		}

		newMaterial := materialer.GetMaterials()
		for artifact, digests := range newMaterial {
			allMaterials[artifact] = digests
		}
	}
	return allMaterials, nil
}

func (ctx *AttestationContext) GetProducts() (map[string]Product, error) {
	allProducts := make(map[string]Product)

	for _, attestor := range ctx.attestors {
		producter, ok := attestor.(Producter)
		if !ok {
			continue
		}

		newProducts := producter.GetProducts()
		for product, digests := range newProducts {
			allProducts[product] = digests
		}
	}
	return allProducts, nil
}
