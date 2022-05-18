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

#!/bin/sh
set -e

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
. "$DIR/../../test/common.sh"

if ! checkprograms make docker ; then
  exit 1
fi

printf "Building witness...\n"
make -C ../../ clean build > /dev/null
cp ../../bin/witness ./witness

printf "Building demo docker image...\n"
docker build -t witness-solarsploit-demo . > /dev/null

printf "\nRunning demo without witness...\n"
docker run --rm -it --cap-add=SYS_PTRACE witness-solarsploit-demo /bin/sh -c "(./solarsploit/solarsploit &);\
  go build -o main main.go && ./main"

printf "\nRunning demo with witness...\n"
docker run --rm -it --cap-add=SYS_PTRACE witness-solarsploit-demo /bin/sh -c "(./solarsploit/solarsploit &);\
  ./witness -c witness.yaml run -- go build -o main main.go && ./main"
