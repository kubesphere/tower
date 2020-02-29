#!/bin/bash
set -e

GV="tower:v1alpha1"

rm -rf ./pkg/client
./hack/generate_group.sh "client,lister,informer" github.com/zryfish/tower/pkg/client github.com/zryfish/tower/pkg/apis "$GV" --output-base=./  -h "$PWD/hack/boilerplate.go.txt"
mv github.com/zryfish/tower/pkg/client ./pkg/
rm -rf ./kubesphere.io
