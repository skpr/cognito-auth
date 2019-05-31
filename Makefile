#!/usr/bin/make -f

export CGO_ENABLED=0

PROJECT=github.com/skpr/cognito-auth
VERSION=$(shell git describe --tags --always)
COMMIT=$(shell git rev-list -1 HEAD)

# Builds the project.
build:
	gox -os='linux darwin' \
	    -arch='amd64' \
	    -output='bin/login_{{.OS}}_{{.Arch}}' \
	    -ldflags='-extldflags "-static" -X github.com/skpr/cognito-auth/cmd.GitVersion=${VERSION} -X github.com/skpr/cognito-auth/cmd.GitCommit=${COMMIT}' \
	    $(PROJECT)

# Run all lint checking with exit codes for CI.
lint:
	golint -set_exit_status `go list ./... | grep -v /vendor/`

# Run tests with coverage reporting.
test:
	go test -cover ./...

IMAGE=skpr/cognito-auth

release-github: build
	ghr -u previousnext "${VERSION}" ./bin/

release: release-github

.PHONY: build lint test release-docker release-github release
