#!/bin/bash
#  Copyright 2023 The Witness Contributors
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

set -e

# Get the latest version of Witness
VERSION=$(curl -s https://api.github.com/repos/testifysec/witness/releases/latest | jq -r '.tag_name')

#remove the 'v' from the version
VERSION=${VERSION:1}

# Determine the architecture of the system
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then
    ARCH="amd64"
fi
if [ "$ARCH" == "aarch64" ]; then
    ARCH="arm64"
fi

### Determine if Arch is supported
if [ $ARCH != "amd64" ] && [ $ARCH != "arm64" ]; then
    echo "Unsupported architecture"
    exit 1
fi

OS=$(uname -s)

## change to lowercase
OS=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
FILENAME="witness_${VERSION}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/testifysec/witness/releases/download/v$VERSION/$FILENAME"
CHECKSUM="$(curl -s  https://github.com/testifysec/witness/releases/download/v$VERSION/witness_${VERSION}_checksums.txt | grep "witness_${VERSION}_${OS}_$ARCH.tar.gz" | awk '{print $1}')"

## Check to see if OS is supported
if [ $OS != "linux" ] && [ $OS != "darwin" ]; then
    echo "Unsupported OS"
    exit 1
fi

# Download the binary
curl -LO $DOWNLOAD_URL

# Verify the checksum
echo "$CHECKSUM witness_${VERSION}_${OS}_${ARCH}.tar.gz | sha256sum -c - "
if [ $? -ne 0 ]; then
    echo "Checksum verification failed, exiting"
    exit 1
fi

# Extract and install the binary
tar -xzf witness_${VERSION}_${OS}_${ARCH}.tar.gz

# Move the binary to /usr/local/bin
sudo mv witness /usr/local/bin/

#Remove the tar.gz file
rm witness_${VERSION}_${OS}_${ARCH}.tar.gz

# Check if the binary is installed
witness version
