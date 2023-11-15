#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)
CSV="$ROOT_DIR/bundle/manifests/compliance-operator.clusterserviceversion.yaml"

OLD_VERSION=$(yq '.spec.version' "$CSV")
echo "$OLD_VERSION"
