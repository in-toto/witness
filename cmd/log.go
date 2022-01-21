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

	"github.com/sirupsen/logrus"
)

type logrusLogger struct {
	l *logrus.Logger
}

func newLogger() *logrusLogger {
	l := logrus.New()
	l.Out = os.Stderr
	f := &logrus.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       true,
	}

	l.SetFormatter(f)
	return &logrusLogger{l}
}

func (l *logrusLogger) SetLevel(levelStr string) error {
	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		return err
	}

	l.l.SetLevel(level)
	return nil
}

func (l *logrusLogger) Errorf(format string, args ...interface{}) {
	l.l.Errorf(format, args...)
}

func (l *logrusLogger) Error(args ...interface{}) {
	l.l.Error(args...)
}

func (l *logrusLogger) Warnf(format string, args ...interface{}) {
	l.l.Warnf(format, args...)
}

func (l *logrusLogger) Warn(args ...interface{}) {
	l.l.Warn(args...)
}

func (l *logrusLogger) Debugf(format string, args ...interface{}) {
	l.l.Debugf(format, args...)
}

func (l *logrusLogger) Debug(args ...interface{}) {
	l.l.Debug(args...)
}

func (l *logrusLogger) Infof(format string, args ...interface{}) {
	l.l.Infof(format, args...)
}

func (l *logrusLogger) Info(args ...interface{}) {
	l.l.Info(args...)
}
