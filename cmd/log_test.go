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

func Test_logrusLogger_LoggingMethods(t *testing.T) {
	tests := []struct {
		name     string
		logFn    func(l *logrusLogger)
		expected logrus.Level
		message  string
	}{
		{
			name: "Error",
			logFn: func(l *logrusLogger) {
				l.Error("error message")
			},
			expected: logrus.ErrorLevel,
			message:  "error message",
		},
		{
			name: "Errorf",
			logFn: func(l *logrusLogger) {
				l.Errorf("error %s", "formatted")
			},
			expected: logrus.ErrorLevel,
			message:  "error formatted",
		},
		{
			name: "Warn",
			logFn: func(l *logrusLogger) {
				l.Warn("warn message")
			},
			expected: logrus.WarnLevel,
			message:  "warn message",
		},
		{
			name: "Warnf",
			logFn: func(l *logrusLogger) {
				l.Warnf("warn %s", "formatted")
			},
			expected: logrus.WarnLevel,
			message:  "warn formatted",
		},
		{
			name: "Debug",
			logFn: func(l *logrusLogger) {
				l.Debug("debug message")
			},
			expected: logrus.DebugLevel,
			message:  "debug message",
		},
		{
			name: "Debugf",
			logFn: func(l *logrusLogger) {
				l.Debugf("debug %s", "formatted")
			},
			expected: logrus.DebugLevel,
			message:  "debug formatted",
		},
		{
			name: "Info",
			logFn: func(l *logrusLogger) {
				l.Info("info message")
			},
			expected: logrus.InfoLevel,
			message:  "info message",
		},
		{
			name: "Infof",
			logFn: func(l *logrusLogger) {
				l.Infof("info %s", "formatted")
			},
			expected: logrus.InfoLevel,
			message:  "info formatted",
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create logger with test hook
			l := logrus.New()
			l.SetLevel(logrus.DebugLevel) // Set to debug to catch all messages
			hook := test.NewLocal(l)
			
			testLogger := &logrusLogger{l: l}
			
			// Execute the log function
			tc.logFn(testLogger)
			
			// Assert the logged message
			require.NotEmpty(t, hook.Entries)
			assert.Equal(t, tc.expected, hook.LastEntry().Level)
			assert.Equal(t, tc.message, hook.LastEntry().Message)
			
			hook.Reset()
		})
	}
}