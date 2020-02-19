#!/bin/bash -x

rm -f cover_nonroot.out cover_root.out coverage.out coverage.html

go test -coverprofile cover_nonroot.out -v && \
    go test -exec sudo -run TestRequiresRoot -coverprofile cover_root.out -v && \
    cat cover_nonroot.out <(grep -v "^mode" cover_root.out) > coverage.out && \
    go tool cover -html=coverage.out -o coverage.html
