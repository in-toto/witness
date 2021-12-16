#! /bin/bash
../bin/witness -c test.yaml run -- go build -o=testapp .
../bin/witness -c test.yaml sign policy.json
../bin/witness -c test.yaml verify