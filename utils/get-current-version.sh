#!/bin/bash

OLD_VERSION=$(git describe --tags --abbrev=0 | tr -d v)
echo "$OLD_VERSION"
