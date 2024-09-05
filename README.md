# imagecheck

The `imagecheck` Golang application checks a container image and its associated
source code and config artifacts for defects and vulnerabilities using multiple
scanners, optionally uploading scan summaries and output to an S3 bucket.

It is intended primarily to be used in a CI/CD pipeline after images are built
and before they are pushed to a container registry to ensure they are safe for use.

It is also intended to be used as a standalone tool for local development and
testing before changes are committed to the repository and pushed to their
upstream remote.

## Organization

This repository is organized as follows:

* [`.github/workflows/release.yaml`](.github/workflows/release.yaml) - GitHub Actions release workflow
* [`app/`](app) - application library source code
* [`cli/`](cli) - application command line interface source code
* [`docs/`](docs) - project documentation hosted on GitHub Pages at https://sambatv.github.io/imagecheck using [docsify](https://docsify.js.org/)
* [`.tool-versions`](.tool-versions) - [asdf](https://asdf-vm.com/)-managed toolchain versions
* [`Dockerfile`](Dockerfile) - application container image build file
* [`go.mod`](go.mod) - application Go module definition
* [`go.sum`](go.sum) - application Go module checksums
* [`Makefile`](Makefile) - project automation for developers
* [`README.md`](README.md) - this document
* [`VERSION`](VERSION) - application version file

## Next steps

[RTFM](https://sambatv.github.io/imagecheck) for more information on how to use
the application.