#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
unformatted=$(find cmd internal -name '*.go' -exec gofmt -l {} +)
if [ -n "$unformatted" ]; then
  printf '%s\n' "$unformatted" >&2
  exit 1
fi
go vet ./...
mkdir -p .cache/unit
go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=.cache/unit/coverage.out -count=1 -timeout=3m ./...
