# Imagecheck

The `imagecheck` application checks a container image, and its associated source
code and config artifacts, for defects and vulnerabilities using multiple
scanners, optionally uploading scan summaries and output to an S3 bucket.

It is intended to be used in a CI/CD pipeline after images are built and before
they are pushed to a container registry to ensure they are safe for use.

It is also intended to be used by developers interactively during local
development and testing before changes are committed to the repository and
pushed to their upstream remote.

## Installation

There are several ways to install `imagecheck` for use:

1. [`install.sh`](#installsh-script) script
2. [`go install`](#go-install) command
3. [`go build`](#go-build) command
4. [`docker pull`](#docker-pull) command

### Scanner dependencies

Scanners are required to be installed on the system. Scanners used by
`imagecheck` include:

* [grype](https://github.com/anchore/grype)
* [trivy](https://https://github.com/aquasecurity/trivy)
* [trufflehog](https://github.com/trufflesecurity/trufflehog)

Note that if using the `imagecheck` Docker image, the scanners are already
installed in that image and in its `$PATH`.

#### Install dependencies with brew

On macOS and Linux, the scanner binaries can be installed using
[Homebrew](https://brew.sh):

```shell
brew install anchore/grype/grype
brew install aquasecurity/trivy/trivy
brew install trufflehog
```

After installation, the `grype`, `trivy`, and `trufflehog` scanner binaries will
be available in your Homebrew `bin` directory. Ensure that this directory is in
your `PATH` environment variable.

```shell
BREW_BIN=$(brew --prefix)/bin
export PATH=$BREW_BIN:$PATH
```

#### Install dependencies with install.sh script

On both Linux and macOS you can also install the scanners from their GitHub
releases using their `install.sh` scripts:

```shell
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b $HOME/bin
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $HOME/bin
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b $HOME/bin
```

### install.sh script

You can install `imagecheck` from [GitHub releases](https://github.com/SambaTV/imagecheck/releases)
using the `install.sh` script:

```shell
curl -sSfL https://raw.githubusercontent.com/sambatv/imagecheck/main/install.sh | sh -s -- -b $HOME/bin
```

After installation, `imagecheck` will be available in your`$HOME/bin` directory.

### go install

The `imagecheck` binary can be installed remotely using the `go` toolchain,
if you have the required Go version 1.23 or higher installed:

```shell
GOBIN=$HOME/bin go install github.com/sambatv/imagecheck@latest
```

After installation, `imagecheck` will be available in your `$HOME/bin` directory.

### go build

You can also build the application locally using the `go` toolchain:

```shell
git clone https://github.com/sambatv/imagecheck.git
cd imagecheck
make build
```

After building, `imagecheck` will be available in the repository `bin/` directory.

### docker pull

The `imagecheck` docker image can be pulled from the `ghci.io` registry:

```shell
docker pull ghcr.io/sambatv/imagecheck:latest
```

After pulling, `imagecheck` can be run from the docker image. The `imagecheck`
binary is the entrypoint for the container image.

Note that the docker image contains the `imagecheck` binary and the binaries
of all the scanners used by it.

For convenience, you may wish to create a shell alias for the `docker run`
command:

```shell
alias imagecheck='docker run -it -v $(pwd):/app --rm ghcr.io/sambatv/imagecheck:latest'
```

## Basic Usage

For details on `imagecheck` usage, add the `-h` or `--help` option to any
command:

```shell
imagecheck --help
```

### Initialization

The `imagecheck init` command should be run first in your git repository root
directory to create a `.imagecheck.json` settings file in it:

```shell
imagecheck init
```

This settings file contains settings used by the `imagecheck scan` command and
is automatically detected by the `imagecheck scan` command when present.

It contains:

* the version of `imagecheck` used to generate the settings file
* the disabled status of all scanning
* the scan settings for all scanners used by `imagecheck` in order of scanning

The generated settings file should be committed to the repository for detection
by the `imagecheck scan` command when run in a build pipeline.

Multiple settings files can be created for different environments and branches,
and can be selected for use with the `--settings`option.

```shell
imagecheck init --settings imagecheck.my.settings.json
```

Note that settings files can be ignored with the `--ignore-settings` option
when running the `imagecheck scan` command.

### Scanning

To run the scanners configured by a loaded settings file or its defaults, use
the `imagecheck scan` command:

```shell
imagecheck scan
```

With default settings, `imagecheck scan` performs:

* a `grype` scan of the built image
* a `trufflehog` scan of the built image

```shell
imagecheck scan $IMAGE
```

This mode of operation is intended for local development and testing.
Read further for details on how to use `imagecheck` in a CI/CD pipeline.

## Pipeline Usage

In a CI/CD pipeline, the `imagecheck scan` command should be run with the
following options, after an image has been built and before it is pushed to
its image registry:

```shell
imagecheck scan --pipeline --build-id BUILD_ID --s3-bucket S3_BUCKET IMAGE 
```

Where:

* `BUILD_ID` is the unique identifier of the build pipeline of the git repository
* `S3_BUCKET` is the name of the S3 bucket to save scan results
* `IMAGE` is the name of the image to scan

If the `--s3-bucket` option is configured, scan results are saved to that S3
bucket, under the `--s3-key-prefix` option, defaulting to `imagecheck`.

Before uploading scan results to S3, scan results are locally cached in the
configured `--cache-dir` directory, defaulting to a `cache` subdirectory in the
current working directory.

The schema for the cache directory hierarchy is as follows:

```text
CACHE_DIR/
  REPO_ID/
    builds/
      BUILD_ID/
        summary.json
        SCAN_TOOL/
          SCAN_TYPE/
            SCAN_TARGET/
                output.json
```

Where:

* `CACHE_DIR` is the name of the S3 bucket to save scan results to
* `REPO_ID` is the unique name of the git repository, e.g. `github.com/sambatv/imagecheck`
* `BUILD_ID` is the unique identifier of the build pipeline of the git repository
* `SCAN_TOOL` is the name of the scanner tool used, e.g. `grype`, `trivy`, `trufflehog`
* `SCAN_TYPE` is the type of scan performed, e.g. `files`, `image`
* `SCAN_TARGET` is the target of the scan, e.g. `ghcr.io/sambatv/imagecheck:latest` image name or some file path

Note that multiple images may be built from a single git repository and its
pipeline. All images should be scanned in build pipelines with the `imagecheck scan`
command before being pushed to their image registry repositories.

When uploading scan results to S3, scan results are uploaded to the configured
`--s3-bucket` directly mapped from the cache directory schema:

```text
S3_BUCKET/
  S3_KEY_PREFIX/
    REPO_ID/
      builds/
        BUILD_ID/
          summary.json
          SCAN_TOOL/
            SCAN_TYPE/
              SCAN_TARGET/
                  output.json
```

Where:

* `S3_BUCKET` is the name of the S3 bucket to save scan results to
* `S3_KEY_PREFIX` is the prefix of the S3 bucket key hierarchy to save scan results under, if any
* `REPO_ID` is the unique name of the git repository, e.g. `github.com/sambatv/imagecheck`
* `BUILD_ID` is the unique identifier of the build pipeline of the git repository
* `SCAN_TOOL` is the name of the scanner tool used, e.g. `grype`, `trivy`, `trufflehog`
* `SCAN_TYPE` is the type of scan performed, e.g. `files`, `image`
* `SCAN_TARGET` is the target of the scan, e.g. `ghcr.io/sambatv/imagecheck:latest` image name or some file path
