#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: sh scripts/build-gateway.sh <gw-version> <output-binary>" >&2
    exit 2
fi
version=$1
case "$version" in
    gw-v*) ;;
    *) echo "version must start with gw-v" >&2; exit 2 ;;
esac
case "$version" in
    *[!a-zA-Z0-9._+-]*) echo "version contains unsupported characters" >&2; exit 2 ;;
esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
toolchain=go$(awk '$1 == "go" { print $2; exit }' go.mod)
CGO_ENABLED=0 GOTOOLCHAIN="$toolchain" GOENV=off GOFLAGS= GOEXPERIMENT= GODEBUG= \
    go build -mod=readonly -tags=noui,notelemetry,noinfisical -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X github.com/Infisical/agent-vault/cmd.version=$version" \
    -o "$2" .
