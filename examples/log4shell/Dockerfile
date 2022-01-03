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

FROM golang:1.17.5-alpine AS rekorbuilder
WORKDIR /src
RUN apk add git
RUN git clone https://github.com/testifysec/rekor && cd rekor/cmd/rekor-cli && git checkout dsse-type && CGO_ENABLED=0 go build -o ./rekor-cli ./main.go

FROM maven:openjdk
WORKDIR /src
COPY --from=rekorbuilder /src/rekor/cmd/rekor-cli/rekor-cli /bin/rekor-cli
COPY ./witness /bin/witness
