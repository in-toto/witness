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

DIR="$(
	cd -- "$(dirname "$0")" >/dev/null 2>&1
	pwd -P
)"

. "$DIR/common.sh"

if ! checkprograms make tar; then
	exit 1
fi

test_config=test.yaml

# if Darwin use test-mac.yaml
if [ "$(uname)" = "Darwin" ]; then
	test_config=test-mac.yaml
fi

make -C ../ build
rm -f ./policy-signed.json ./build.attestation.json ./package.attestation.json ./fail.attestation.json ./testapp ./testapp.tar.tgz
echo "testing signing policy"
../bin/witness -c $test_config -l debug sign -f policy.json

# successful test
echo "testing witness run on build step"
../bin/witness -c $test_config run -o build.attestation.json -- go build -o=testapp .
echo "testing witness run on packaging step"
../bin/witness -c $test_config run -s package -k ./testkey2.pem -o package.attestation.json -- tar czf ./testapp.tar.tgz ./testapp
echo "testing witness verify"
../bin/witness -c $test_config verify

# make sure we fail if we run with a key not in the policy
echo "testing that witness verify fails with a key not in the policy"
../bin/witness -c $test_config run -k failkey.pem -o ./fail.attestation.json -- go build -o=testapp .
../bin/witness -c $test_config run -s package -k ./testkey2.pem -o package.attestation.json -- tar czf ./testapp.tar.tgz ./testapp
set +e
if ../bin/witness -c $test_config verify -a ./fail.attestation.json -a ./package.attestation.json; then
	echo "expected verify to fail"
	exit 1
fi

# test policy with multi-type attestor (ie. SBOM)
# test SPDX with subject digest for the name
../bin/witness verify -p spdx-sbom-policy-signed.json -a spdx-att.json -k testpub.pem -s 54c5b3dd459d5ef778bb2fa1e23a5fb0e1b62ae66970bcb436e8f81a1a1a8e41 --log-level debug
# test CycloneDX with subject digest for the name
../bin/witness verify -p cdx-sbom-policy-signed.json -a cdx-att.json -k testpub.pem -s 54c5b3dd459d5ef778bb2fa1e23a5fb0e1b62ae66970bcb436e8f81a1a1a8e41 --log-level debug
