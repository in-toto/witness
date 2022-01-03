#!/bin/sh
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


set -e

printf "Building witness...\n"
make -C ../../ clean build > /dev/null
cp ../../bin/witness ./witness

printf "Building demo docker image...\n"
docker build -t witness-log4shell-demo .

printf "Building demo projects...\n"
docker run --rm -it --net host -v "$(pwd):/src" -w /src/vuln witness-log4shell-demo witness run -c ../witness.yaml -- mvn package
docker run --rm -it --net host -v "$(pwd):/src" -w /src/nonvuln witness-log4shell-demo witness run -c ../witness.yaml -- mvn package
