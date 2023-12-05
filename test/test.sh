#! /bin/sh

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

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
. "$DIR/common.sh"

if ! checkprograms make tar ; then
  exit 1
fi

make -C ../ build
rm -f ./policy-signed.json ./build.attestation.json ./package.attestation.json ./fail.attestation.json ./testapp ./testapp.tar.tgz
../bin/witness -c test.yaml -l debug sign -f policy.json

# successful test
../bin/witness -c test.yaml run -o build.attestation.json -- go build -o=testapp .
../bin/witness -c test.yaml run -s package -k ./testkey2.pem -o package.attestation.json -- tar czf ./testapp.tar.tgz ./testapp
../bin/witness -c test.yaml verify

# make sure we fail if we run with a key not in the policy
../bin/witness -c test.yaml run -k failkey.pem -o ./fail.attestation.json  -- go build -o=testapp .
../bin/witness -c test.yaml run -s package -k ./testkey2.pem -o package.attestation.json -- tar czf ./testapp.tar.tgz ./testapp
set +e
if ../bin/witness -c test.yaml verify -a ./fail.attestation.json -a ./package.attestation.json; then
  echo "expected verify to fail"
  exit 1
fi
