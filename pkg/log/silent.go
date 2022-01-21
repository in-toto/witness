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

package log

// SilentLogger is an implementation of the Logger interface that suppresses
// all logging output. This is the default logger when using Witness as a
// library, so that we don't interfere with the caller's stdout/stderr. Callers
// should supply their own Logger to capture Witness logging if desired.
type SilentLogger struct{}

func (l SilentLogger) Errorf(format string, args ...interface{}) {}
func (l SilentLogger) Error(args ...interface{})                 {}
func (l SilentLogger) Warnf(format string, args ...interface{})  {}
func (l SilentLogger) Warn(args ...interface{})                  {}
func (l SilentLogger) Debugf(format string, args ...interface{}) {}
func (l SilentLogger) Debug(args ...interface{})                 {}
func (l SilentLogger) Infof(format string, args ...interface{})  {}
func (l SilentLogger) Info(args ...interface{})                  {}
