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

#set -e

cd ..
go mod tidy
go mod vendor
make
cd dev || exit

RED='\033[0;31m'

sha=$(git rev-parse --short HEAD)
tag=$(git describe --tags "$(git rev-list --tags --max-count=1)")
imagetag=registry.gitlab.com/testifysec/demos/witness-demo/builder:"${tag}"-"${sha}"-golang-1.17.3


docker build -f ./Dockerfile.go-builder -t "${imagetag}" ./../
docker push "${imagetag}"

printf "Published witness image to:\n%s%s\n" "${RED}" "${imagetag}"

IFS=" " read -r -a nodeIDs <<< "$(kubectl -n spire exec -it spire-server-0 -- /opt/spire/bin/spire-server agent list | grep 'spiffe://dev.testifysec.com/spire/agent/gcp_iit' | cut -f 2- -d ':' | tr -d ' ' | tr -d '\r'))"

for node in "${nodeIDs[@]}"; do
kubectl exec -n spire spire-server-0 -- \
    /opt/spire/bin/spire-server entry create \
    -parentID "${node}" \
    -spiffeID spiffe://dev.testifysec.com/witness-demo/builder \
    -selector k8s:container-image:"${imagetag}" \
    -selector k8s:ns:gitlab-runner
done
