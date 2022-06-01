# Copyright 2022 The Witness Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#/bin/sh
checkprograms() {
  local result=0
  for prog in "$@"
  do
    if ! command -v $prog > /dev/null; then
      printf "$prog is required to run this script. please ensure if is installed and in your PATH\n"
      result=1
    fi
  done

  return $result
}
