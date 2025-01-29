# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL := /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# -----------------------------------------------------------------------------
# Define build variables
# -----------------------------------------------------------------------------

# Set app identity.
APP_NAME ?= imagecheck
APP_VERSION ?= $(shell cat VERSION)

# Set Docker image build configuration.
DOCKERFILE ?= Dockerfile

# Set git repo identity
GIT_COMMIT ?= $(shell git rev-parse HEAD)
GIT_DIRTY  ?= $(shell test -n "`git status --porcelain`" && echo "-dirty" || true)
GIT_TAG = "$(GIT_COMMIT)$(GIT_DIRTY)"

# Set Go compiler and linker flags
GO_PACKAGE ?= github.com/sambatv/$(APP_NAME)
GO_LDFLAGS = -ldflags "-X $(GO_PACKAGE)/metadata.Version=$(APP_VERSION)"

# Set image registry configuration.
REGISTRY_HOSTNAME   = ghcr.io
REGISTRY_REPOSITORY = $(REGISTRY_HOSTNAME)/sambatv/$(APP_NAME)

# Set image identity configuration.
# By default, only build and push images tagged with the git commit short hash.
IMAGE = $(REGISTRY_REPOSITORY):$(GIT_TAG)
IMAGE_LATEST = $(REGISTRY_REPOSITORY):latest
# If the RELEASE environment variable is set to anything, additionally
# push images tagged with the app version.
ifneq ($(RELEASE),)
  IMAGE_VERSIONED = $(REGISTRY_REPOSITORY):v$(APP_VERSION)
endif

# -----------------------------------------------------------------------------
# Define build targets
# -----------------------------------------------------------------------------

# Display help information by default.
.DEFAULT_GOAL := help

##@ Info targets

# The 'help' target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
#
# See https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters for more
# info on the usage of ANSI control characters for terminal formatting.
#
# See http://linuxcommand.org/lc3_adv_awk.php for more info on the awk command.

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: vars
vars: ## Show environment variables used by this Makefile
	@echo "APP_NAME:            $(APP_NAME)"
	@echo "APP_VERSION:         $(APP_VERSION)"
	@echo "GIT_COMMIT:          $(GIT_COMMIT)"
	@echo "GIT_TAG:             $(GIT_TAG)"
	@echo "GO_PACKAGE:          $(GO_PACKAGE)"
	@echo "GO_LDFLAGS:          $(GO_LDFLAGS)"
	@echo "REGISTRY_HOSTNAME:   $(REGISTRY_HOSTNAME)"
	@echo "REGISTRY_REPOSITORY: $(REGISTRY_REPOSITORY)"
	@echo "IMAGE:               $(IMAGE)"
ifneq ($(RELEASE),)             
	@echo "IMAGE_VERSIONED:     $(IMAGE_VERSIONED)"
endif

##@ Dependency targets

.PHONY: deps
deps: ## Install all scanner dependency binaries
	@echo
	@echo 'installing scanners ...'
	mkdir -p ./bin
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ./bin
	curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ./bin
	curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ./bin

##@ Application targets

.PHONY: build
build: ## Build the application binary
	@echo
	@echo 'building $(APP_NAME) ...'
	CGO_ENABLED=0 go build $(GO_LDFLAGS) -tags netgo,osusergo -o ./bin/$(APP_NAME) .

.PHONY: lint
lint: ## Lint the application
	@echo
	@echo 'linting $(APP_NAME) ...'
	go vet ./...

.PHONY: test
test: ## Run the application tests
	@echo
	@echo 'testing $(APP_NAME) ...'
	go test -v ./...

.PHONY: clean
clean: ## Clean application and all scanner dependency binaries
	@echo
	@echo 'cleaning $(APP_NAME) build artifacts ...'
	rm -rf ./bin

##@ Image targets

.PHONY: image-build
image-build: ## Build the container image
	@echo
	@echo 'building image $(IMAGE_VERSIONED) ...'
	DOCKER_BUILDKIT=1 DOCKER_CLI_HINTS=false docker build -t $(IMAGE) .
ifneq ($(RELEASE),)
	@echo
	@echo 'tagging versioned image $(IMAGE_VERSIONED)'
	docker tag $(IMAGE) $(IMAGE_VERSIONED)
else
	@echo
	@echo 'tagging latest image $(IMAGE)'
	docker tag $(IMAGE) $(IMAGE_LATEST)
endif

.PHONY: image-scan
image-scan: build ## Scan the container image for defects and vulnerabilities
	@echo
	@echo 'scanning image $(IMAGE) ...'
	./bin/$(APP_NAME) scan --force $(IMAGE)

##@ Release targets

.PHONY: tag-release
tag-release: ## Tag application release and push to origin
ifeq ($(RELEASE),)
	@echo
	@echo 'RELEASE not defined, skipping release'
	@exit 1
else ifneq ($(DIRTY),)
	@echo
	@echo 'git repository state is dirty, skipping release'
	@exit 1
else
	@echo
	@echo 'releasing $(APP_NAME) ...'
	git tag -a v$(APP_VERSION) -m "Release v$(APP_VERSION)"
	git push origin v$(APP_VERSION)
endif
