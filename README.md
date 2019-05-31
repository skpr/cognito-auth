# Cognito Auth

[![CircleCI](https://circleci.com/gh/skpr/cognito-auth.svg?style=svg)](https://circleci.com/gh/skpr/cognito-auth)

**Maintainer**: Kim Pepper

Cognito Auth is a Go package for authenticating with AWS Cognito from the command line.

## Development

### Getting started

To work on this project you will first need Go installed on your machine.

#### Setup

First make sure Go is properly installed and that a GOPATH has been set. You will also need to add $GOPATH/bin to your $PATH. For steps on getting started with Go: https://golang.org/doc/install

Next, using Git, clone this repository into $GOPATH/src/github.com/skpr/cognito-auth. All the necessary dependencies are either vendored or automatically installed, so you just need to type `make test`. This will run the tests and compile the binary. If this exits with exit status 0, then everything is working!

```bash
$ cd "$GOPATH/src/github.com/skpr/cognito-auth"
$ make test
```

To compile a development version of cognito-auth, run `make build`. This will build everything using gox and put binaries in the bin and $GOPATH/bin folders:

```bash
$ make build
...

# Linux:
$ bin/cognito_auth_linux_amd64 --help

# OSX:
$ bin/cognito_auth_darwin_amd64 --help
```

### Dependencies

cognito-auth use [Go Modules](https://blog.golang.org/using-go-modules) for managing dependencies.

### Documentation

See `/docs`

### Tooling

Testing:

```bash
go get -u github.com/golang/lint/golint
```

Release management:
```bash
go get -u github.com/tcnksm/ghr
```

Build:
```
go get -u github.com/mitchellh/gox
```

#### Releases

Release artifacts are pushed to the [github releases page](https://github.com/skpr/cognito-auth/releases) when tagged
properly. Use [semantic versioning](http://semver.org/) prefixed with `v` for version scheme. Examples:

- `v1.0.0`
- `v1.1.0-beta1`
