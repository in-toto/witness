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
. "$DIR/common.sh"

if ! checkprograms make ko ; then
  exit 1
fi

make -C ../ build
rm -f out.tar
KO_DOCKER_REPO=null ../bin/witness run -c test.yaml -a oci --trace=false -- ko publish --push=false --tarball out.tar .
