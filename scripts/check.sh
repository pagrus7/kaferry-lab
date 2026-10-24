#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
unformatted=$(find cmd internal -name '*.go' -exec gofmt -l {} +)
if [ -n "$unformatted" ]; then
  printf '%s\n' "$unformatted" >&2
  exit 1
fi
go vet ./...
go test -race -count=1 -timeout=3m ./...
