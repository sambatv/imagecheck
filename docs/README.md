# imagecheck

The `imagecheck` application checks a container image and its associated source
code and config artifacts for defects and vulnerabilities using multiple
scanners, optionally uploading scan summaries and output to an S3 bucket.

It is intended primarily to be used in a CI/CD pipeline after images are built
and before they are pushed to a container registry. This is to ensure they are
safe for use.

It is also intended to be used as a standalone tool for local development and
testing before changes are committed to git repositories and pushed to their
upstream remotes.

## Installation

### Dependencies

All scanners are required to be installed on the system.

On macOS and Linux, they can be installed using [Homebrew](https://brew.sh):

```shell
brew install anchore/grype/grype
brew install aquasecurity/trivy/trivy
brew install trufflehog
```

After installation, the `grype`, `trivy`, and `trufflehog` binaries will be
available in your Homebrew `bin` directory. Ensure that this directory is in
your `PATH` environment variable.

```shell
BREW_BIN=$(brew --prefix)/bin
export PATH=$BREW_BIN:$PATH
```

On both Linux and macOS you can also install the scanners from their GitHub
releases using their `install.sh` scripts:

```shell
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b $HOME/bin
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $HOME/bin
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b $HOME/bin
```

Note that if running the docker image, the scanners are already installed
and available in the container.

### Use install.sh script

You can install the application from its GitHub releases using the `install.sh` script:

```shell
curl -sSfL https://raw.githubusercontent.com/sambatv/imagecheck/main/install.sh | sh -s -- -b $HOME/bin
```

After installation, the `imagecheck` binary will be available in your
`$HOME/bin` directory.

### Use go install

The `imagecheck` binary can be installed using the `go` toolchain:

```shell
GOBIN=~/bin go install github.com/sambatv/imagecheck@latest
```

After installation, the `imagecheck` binary will be available in your
`$HOME/bin` directory.

### Use local build

You can also build the application locally:

```shell
git clone https://github.com/sambatv/imagecheck.git
cd imagecheck
make build
```

After building, the `imagecheck` binary will be available in the repository
root directory.

### Use docker image from ghci.io registry

The `imagecheck` docker image can be pulled from the `ghci.io` registry:

```shell
docker pull ghcr.io/sambatv/imagecheck:latest
```

After pulling, the `imagecheck` binary can be run from the docker image.

```shell
docker run -it --rm ghcr.io/sambatv/imagecheck:latest --help 
```

The `imagecheck` binary is the entrypoint for the container image.

Note that the docker image contains the `imagecheck` binary and the binaries
of all the scanners used by it. 

## Usage

For details on `imagecheck` usage, add the `-h` or `--help` option to any
command:

```shell
imagecheck --help
```

### Scanning

The `imagecheck scan` command drives the following open-source scanners:

* [grype](https://github.com/anchore/grype)
* [trivy](https://https://github.com/aquasecurity/trivy)
* [trufflehog](https://github.com/trufflesecurity/trufflehog)

When run with no arguments, it performs the following checks:

* A `grype` scan of the repository filesystem
* A `trivy` scan of the repository filesystem and config, including the Dockerfile
* A `trufflehog` scan of the repository filesystem

If an image argument is provided, it performs the following additional checks:

* A `grype` scan of the built image
* A `trufflehog` scan of the built image

```shell
imagecheck scan $IMAGE
```

This mode of operation is intended for local development and testing.
Read further for details on how to use `imagecheck` in a CI/CD pipeline.

### Reporting

In a CI/CD pipeline, the `imagecheck scan` command should be run with the
following options, after an image has been built and before it is pushed to
its image registry:

```shell
imagecheck \
  --s3-bucket $S3_BUCKET \
  --s3-key-prefix $S3_KEY_PREFIX \
  --git-repo $REPO_NAME \
  --build $BUILD_ID \
  scan $IMAGE 
```

Where:

* `S3_BUCKET` is the name of the S3 bucket to save scan results to
* `S3_PREFIX` is the prefix of the S3 bucket key hierarchy to save scan results under, if any
* `REPO_NAME` is the unique name of the git repository, e.g. `github.com/sambatv/imagecheck`
* `BUILD_ID` is the unique identifier of the build pipeline of the git repository
* `IMAGE` is the name of the image to scan

If the `--s3-bucket` option is configured, scan results are saved to that S3
bucket, under the `--s3-key-prefix` option, with the following key hierarchy.

```text
S3_KEY_PREFIX/
  REPO_NAME/
    BUILD_ID/
      report.json
      sbom.json
      scans/
        grype/
          files.json
          IMAGE.json
        trivy/
          config.json
          files.json
        trufflehog/
          files.json
          IMAGE.json
```

Where:

* `REPO_NAME` is the git repository name (e.g. `github.com/sambatv/imagecheck`) specified with the `--git-repo` option
* `BUILD_ID` is the unique git build pipeline id specified with the `--build-id` option
* `IMAGE` is the image passed as argument to the `scan` command

Note that multiple images may be built from a single repository and its pipeline.
