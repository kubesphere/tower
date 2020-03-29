#!/bin/bash
set -e

GV="tower:v1alpha1"

rm -rf ./pkg/client
./hack/generate_group.sh "client,lister,informer" kubesphere.io/tower/pkg/client kubesphere.io/tower/pkg/apis "$GV" --output-base=./  -h "$PWD/hack/boilerplate.go.txt"
mv kubesphere.io/tower/pkg/client ./pkg/
rm -rf ./kubesphere.io
