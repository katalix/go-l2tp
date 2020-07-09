#!/bin/bash -x

SUBDIRS=$(find . -name "*_test.go" | xargs grep -rl TestRequiresRoot | { while read l; do dirname $l; done } | sort | uniq)

rm -f coverage.out coverage.html

go test -coverprofile coverage.out -v ./... || exit 1
for sub in $SUBDIRS; do
    go test -exec sudo -run TestRequiresRoot -coverprofile coverage.tmp $sub && \
        grep -v "^mode" coverage.tmp >> coverage.out && \
        rm coverage.tmp || \
        exit 1
done

go tool cover -html=coverage.out -o coverage.html
