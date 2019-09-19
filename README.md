# Cognito Auth

[![CircleCI](https://circleci.com/gh/skpr/cognito-auth.svg?style=svg)](https://circleci.com/gh/skpr/cognito-auth)

**Maintainer**: Kim Pepper

Cognito Auth is a Go package for authenticating with AWS Cognito from the command line.

## Commands

Two modes of authentication are supported:

- Cognito User Pool Authentication
- Google Authentication

```
  help [<command>...]
    Show help.

  google login [<flags>]
    Logs in a user using their google account.

  userpool login --username=USERNAME [<flags>]
    Logs in a user to a Cognito Userpool.

  userpool logout [<flags>]
    Logs out a user from a Cognito Userpool

  userpool reset-password --username=USERNAME [<flags>]
    Resets a users Cognito Userpool password.
```

Once a user has logged in, they are able to generate a one-time sign in URL to the 
AWS Console:

```
  console-signin [<flags>]
    Generates a console sign-in link.
```


## Configuration

### User Pool Authentication

Cognito Auth looks for a configuration file in `$HOME/.config/cognito-auth/userpool.yml`.

Example configuration:

```yaml
identity_provider_id: <YOUR IDENTITY PROVIDER ID> 
identity_pool_id: <YOUR IDENTITY POOL ID>
client_id: <YOUR CLIENT ID>
console_destination: https://console.aws.amazon.com/cloudwatch
console_issuer: <YOUR CONSOLE ISSUER URL>
```

*Note:* `client_secret` is optional for User Pool Authentication.

By default, it will store OAuth2 tokens and AWS STS Credentials in yaml *files* in `$HOME/Library/Caches/cognito-auth/` (MacOS)
or `$HOME/.cache/cognito-auth/` (Linux).

### Google Authentication

Cognito Auth looks for a configuration file in `$HOME/.config/cognito-auth/google.yml`.

```
identity_provider_id: accounts.google.com
identity_pool_id: <YOUR IDENTITY POOL ID>
client_id: <YOUR CLIENT ID>
client_secret: <YOUR CLIENT SECRET>
console_destination: https://console.aws.amazon.com/cloudwatch
console_issuer: <YOUR CONSOLE ISSUER URL>
```

The Google Authentication uses the code flow. You will be presented with a page displaying an
authorisation code. You need to copy and past that into the console when prompted.

*Note:* `client_secret` is required for Google Authentication.

### Secure Token Storage

Cognito Auth allows you to store OAuth2 tokens and AWS Credentials in a OS-native keychain.

To enable this feature, add the following lines to the configuration:

```yaml
creds_store: native
creds_oauth_key: Cognito OAuth Tokens
creds_aws_key: Cognito AWS Credentials
``` 

`creds_oauth_key` and `creds_aws_key` are used as the unque keychain item key for storage.
 
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

#### Releases

Release artifacts are pushed to the [github releases page](https://github.com/skpr/cognito-auth/releases) when tagged
properly. Use [semantic versioning](http://semver.org/) prefixed with `v` for version scheme. Examples:

- `v1.0.0`
- `v1.1.0-beta1`
