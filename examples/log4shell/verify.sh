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

#!/bin/sh
set -e

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
. "$DIR/../../test/common.sh"

if ! checkprograms docker ; then
  exit 1
fi


printf "\nVerifying policy on nonvulnerable package...\n"
docker run --rm -it --net host -v "$(pwd):/src" -w /src/nonvuln witness-log4shell-demo witness verify -c ../witness.yaml --artifactfile target/my-app-1.0-SNAPSHOT.jar

printf "\nVerifying policy on vulnerable package...\n"
docker run --rm -it --net host -v "$(pwd):/src" -w /src/vuln witness-log4shell-demo witness verify -c ../witness.yaml --artifactfile target/my-app-1.0-SNAPSHOT.jar

