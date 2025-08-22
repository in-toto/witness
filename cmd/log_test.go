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

package cmd

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newLogger(t *testing.T) {
	logger := newLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logger.l)

	// Check if the logger has the expected configuration
	assert.Equal(t, os.Stderr, logger.l.Out)

	// Validate formatter settings
	formatter, ok := logger.l.Formatter.(*logrus.TextFormatter)
	require.True(t, ok)
	assert.True(t, formatter.DisableLevelTruncation)
	assert.True(t, formatter.PadLevelText)
	assert.True(t, formatter.DisableTimestamp)
}

func Test_logrusLogger_SetLevel(t *testing.T) {
	logger := newLogger()

	// Test valid log levels
	validLevels := []string{
		"debug", "info", "warn", "error", "fatal", "panic",
	}

	for _, level := range validLevels {
		err := logger.SetLevel(level)
		require.NoError(t, err)
	}

	// Test invalid log level
	err := logger.SetLevel("invalid-level")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid logrus Level")
}

func Test_logrusLogger_Error(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Error("error message")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	assert.Equal(t, "error message", hook.LastEntry().Message)
}

func Test_logrusLogger_Errorf(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Errorf("error %s", "formatted")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	assert.Equal(t, "error formatted", hook.LastEntry().Message)
}

func Test_logrusLogger_Warn(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Warn("warn message")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
	assert.Equal(t, "warn message", hook.LastEntry().Message)
}

func Test_logrusLogger_Warnf(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Warnf("warn %s", "formatted")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
	assert.Equal(t, "warn formatted", hook.LastEntry().Message)
}

func Test_logrusLogger_Debug(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Debug("debug message")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Equal(t, "debug message", hook.LastEntry().Message)
}

func Test_logrusLogger_Debugf(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Debugf("debug %s", "formatted")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Equal(t, "debug formatted", hook.LastEntry().Message)
}

func Test_logrusLogger_Info(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Info("info message")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	assert.Equal(t, "info message", hook.LastEntry().Message)
}

func Test_logrusLogger_Infof(t *testing.T) {
	logger := newLogger()
	hook := test.NewLocal(logger.l)
	logger.l.SetLevel(logrus.DebugLevel)

	logger.Infof("info %s", "formatted")

	require.NotEmpty(t, hook.Entries)
	assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	assert.Equal(t, "info formatted", hook.LastEntry().Message)
}
