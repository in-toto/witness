#! /bin/bash
# Copyright 2021 The Witness Contributors
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

make -C ../ build
rm -f ./test-attestation.demo ./testapp ./policy-signed.json
../bin/witness -c test.yaml run -- go build -o=testapp .
../bin/witness -c test.yaml sign -f policy.json
../bin/witness -c test.yaml verify
