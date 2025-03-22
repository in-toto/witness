// Copyright 2025 The Witness Contributors
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

package errors

import (
	"errors"
	"fmt"
)

// AttestorError represents an error that occurred during attestation generation
type AttestorError struct {
	Err error
	AttestorName string
}

func (e *AttestorError) Error() string {
	return fmt.Sprintf("attestor error (%s): %v", e.AttestorName, e.Err)
}

func (e *AttestorError) Unwrap() error {
	return e.Err
}

// NewAttestorError creates a new AttestorError
func NewAttestorError(attestorName string, err error) *AttestorError {
	return &AttestorError{
		Err: err,
		AttestorName: attestorName,
	}
}

// IsAttestorError checks if the given error is or wraps an AttestorError
func IsAttestorError(err error) bool {
	var attestorErr *AttestorError
	return errors.As(err, &attestorErr)
}

// InfrastructureError represents an error related to infrastructure operations
// such as signing, storing artifacts, or interacting with external services
type InfrastructureError struct {
	Err error
	Operation string
}

func (e *InfrastructureError) Error() string {
	return fmt.Sprintf("infrastructure error (%s): %v", e.Operation, e.Err)
}

func (e *InfrastructureError) Unwrap() error {
	return e.Err
}

// NewInfrastructureError creates a new InfrastructureError
func NewInfrastructureError(operation string, err error) *InfrastructureError {
	return &InfrastructureError{
		Err: err,
		Operation: operation,
	}
}

// IsInfrastructureError checks if the given error is or wraps an InfrastructureError
func IsInfrastructureError(err error) bool {
	var infraErr *InfrastructureError
	return errors.As(err, &infraErr)
}