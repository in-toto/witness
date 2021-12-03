#! /bin/bash
set -e

cd ..
go mod tidy
go mod vendor
go build -o ./bin/witness
cd dev

RED='\033[0;31m'

sha=$(git rev-parse --short HEAD)
tag=$(git describe --tags $(git rev-list --tags --max-count=1))
imagetag=`echo registry.gitlab.com/testifysec/witness/builder:${tag}-${sha}-golang-1.17.3`


docker build -f ./Dockerfile.go-builder -t ${imagetag} ./../
docker push ${imagetag}

printf "Published witness image to:\n${RED}${imagetag}\n"

nodeIDs=($(kubectl -n spire exec -it spire-server-0 -- /opt/spire/bin/spire-server agent list | grep 'spiffe://dev.testifysec.com/spire/agent/gcp_iit' | cut -f 2- -d ':' | tr -d ' ' | tr -d '\r'))

for node in ${nodeIDs[@]}; do
kubectl exec -n spire spire-server-0 -- \
    /opt/spire/bin/spire-server entry create \
    -parentID ${node} \
    -spiffeID spiffe://dev.testifysec.com/witness-demo/builder \
    -selector k8s:container-image:${imagetag} \
    -selector k8s:ns:gitlab-runner
done
