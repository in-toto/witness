---
title: "How to Write Attestors"
description: "A short guide explaining how to write custom attestors for Witness."
---

# How to Write Attestors

This guide explains how to write new attestors in the `go-witness` library so they can be integrated with Witness.

## Overview

In `witness`, an attestor is implemented by satisfying the `attestation.Attestor` interface. Attestors are components that gather details about a process, application, or environment and package that information into an `in-toto` attestation predicate.

To write a new attestor, you need to:
1. Define a struct that implements the `Attestor` interface.
2. Implement the `Attest()`, `Name()`, `Type()`, `RunType()`, and `Schema()` methods.
3. Register your attestor in its package `init()` function calling `attestation.RegisterAttestation`.

## The Attestor Interface

The main interface you need to implement looks roughly like this:

```go
type Attestor interface {
    Name() string
    Type() string
    RunType() RunType
    Schema() *jsonschema.Schema
    Attest(ctx *AttestationContext) error
}
```

## Walkthrough: A Simple Example (JWT Attestor)

Let's walk through an existing attestor in the core library, the `jwt` attestor, to understand how the components fit together. This attestor fetches a JSON Web Key form a JWKS endpoint, parses a provided token, and extracts its claims as evidence.

### 1. Defines Constants

First, define standard values for the attestor: name, the schema URI, and the lifecycle phase (e.g., Pre-Material, Post-Material, etc.).

```go
package jwt

import (
    "github.com/in-toto/go-witness/attestation"
)

const (
    Name    = "jwt"
    Type    = "https://witness.dev/attestations/jwt/v0.1"
    RunType = attestation.PreMaterialRunType
)
```

### 2. Implement the Struct

Define the struct and its properties. Standard pattern involves defining functional options for configuration and using `json` tags. Properties exported on the struct will be serialized in the final attestation predicate!

```go
type Attestor struct {
    Claims     map[string]interface{} `json:"claims"`
    VerifiedBy VerificationInfo       `json:"verifiedBy,omitempty"`
    jwksUrl    string
    token      string
}
```

### 3. Implement Attestor Methods

Next, you provide the `Name()`, `Type()`, `RunType()`, and `Schema()` getter functions that return our declared constants and automatic JSON schema mapping.

```go
import "github.com/invopop/jsonschema"

func (a *Attestor) Name() string { return Name }
func (a *Attestor) Type() string { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema {
    return jsonschema.Reflect(&a)
}
```

### 4. Implement the Execution Logic

The `Attest` function encapsulates the core business logic of collecting evidence or metadata as part of the pipeline.

```go
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
    if a.token == "" {
        return fmt.Errorf("invalid token")
    }

    // Example logic checking and parsing the JWT.
    // Real implementation goes out over HTTP to test the jwksUrl
    // and extract the claims onto the property.

    a.Claims = map[string]interface{}{"valid": true}

    return nil
}
```

### 5. Register the Attestor

Finally, register the provider in a self-initializing block with `attestation.RegisterAttestation`.
This allows Witness registries to automatically discover and execute it during a run.

```go
func init() {
    attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
        return New()
    })
}
```

## Adding to Witness Configuration

Once added to `go-witness`, you also need to ensure that the new attestor is registered inside `witness`'s command options struct (`options/run.go` in the main CLI). This allows arguments to be dynamically parsed from user inputs to configure your `Attestor` instance.
