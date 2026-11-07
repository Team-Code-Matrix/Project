#!/usr/bin/env bash
# Compile Protobuf definitions into Go and Python stubs
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Compiling Protobufs for Go and Python..."

# Output dirs
mkdir -p ../gen/go
mkdir -p ../gen/python

protoc --proto_path=. \
  --go_out=../gen/go --go_opt=paths=source_relative \
  --python_out=../gen/python \
  *.proto

echo "Protobuf compilation successful."

