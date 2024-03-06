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

package options

import (
	"github.com/spf13/cobra"
)

type RootOptions struct {
	Config         string
	LogLevel       string
	CpuProfileFile string
	MemProfileFile string
}

func (ro *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&ro.Config, "config", "c", ".witness.yaml", "Path to the witness config file")
	cmd.PersistentFlags().StringVarP(&ro.LogLevel, "log-level", "l", "info", "Level of logging to output (debug, info, warn, error)")
	cmd.PersistentFlags().StringVar(&ro.CpuProfileFile, "debug-cpu-profile-file", "", "Path to store the CPU profile. Profiling will be enabled if this is non-empty")
	cmd.PersistentFlags().StringVar(&ro.MemProfileFile, "debug-mem-profile-file", "", "Path to store the Memory profile. Profiling will be enabled if this is non-empty")
}
