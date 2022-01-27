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

printf "\nFinding artifacts with log4j 1.2.17...\n"
LOG4JHASH=$(echo -n dependency:log4j/log4j@1.2.17 | sha256sum | awk '{print $1}')
entryuuid=$(docker run --rm -it --net host witness-log4shell-demo rekor-cli --rekor_server http://localhost:3000 search --sha "$LOG4JHASH" |\
  awk '/Found matching entries/{getline; print}' | tr -d '\r')

docker run --rm -it --net host witness-log4shell-demo rekor-cli --rekor_server=http://localhost:3000 get --uuid $entryuuid --format json |\
  jq -r '.Attestation' | \
  jq -r '.subject[] | select(.name | endswith(".jar")) | .' 
