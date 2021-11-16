package attestation

import (
	"context"
	"crypto"
	"fmt"
	"os"
)

type ErrInvalidOption struct {
	Option string
	Reason string
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

type AttestationContext struct {
	ctx                context.Context
	attestors          []Attestor
	workingDir         string
	hashes             []crypto.Hash
	completedAttestors []Attestor
}

func NewContext(attestors []Attestor, opts ...AttestationContextOption) (*AttestationContext, error) {
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
	}

	for _, opt := range opts {
		opt(ctx)
	}

	return ctx, nil
}

func (ctx *AttestationContext) RunAttestors() error {
	for _, attestor := range ctx.attestors {
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
