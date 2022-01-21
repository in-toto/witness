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

var log Logger = SilentLogger{}

// Logger is used by witness library code to print out relevant information at runtime.
type Logger interface {
	Errorf(format string, args ...interface{})
	Error(args ...interface{})
	Warnf(format string, args ...interface{})
	Warn(args ...interface{})
	Debugf(format string, args ...interface{})
	Debug(args ...interface{})
	Infof(format string, args ...interface{})
	Info(args ...interface{})
}

// SetLogger will set the Logger instance that all Witness library code will use as logging output.
// The default is a SilentLogger that will output nothing.
func SetLogger(l Logger) {
	log = l
}

// GetLogger returns the Logger instance currently being used by Witness library code.
func GetLogger() Logger {
	return log
}

func Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

func Error(args ...interface{}) {
	log.Error(args...)
}

func Warnf(format string, args ...interface{}) {
	log.Warnf(format, args...)
}

func Warn(args ...interface{}) {
	log.Warn(args...)
}

func Debugf(format string, args ...interface{}) {
	log.Debugf(format, args...)
}

func Debug(args ...interface{}) {
	log.Debug(args...)
}

func Infof(format string, args ...interface{}) {
	log.Infof(format, args...)
}

func Info(args ...interface{}) {
	log.Info(args...)
}
