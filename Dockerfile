FROM golang:1.23.0-bookworm AS builder
RUN apt-get update && apt-get upgrade && apt-get install --no-install-recommends -y curl git make
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

FROM debian:bookworm-slim
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY --from=builder /app/imagecheck /usr/local/bin/
RUN useradd -u 1001 -ms /bin/bash app
USER app
WORKDIR /home/app
ENTRYPOINT ["/usr/local/bin/imagecheck"]
