FROM golang:1.23.1-alpine3.20 AS builder
RUN apk update && apk upgrade && apk add --no-cache bash curl git make shadow
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

FROM alpine:3.20.3
RUN apk update && apk upgrade
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY --from=builder /app/bin/imagecheck /usr/local/bin/
USER 1001:1001
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/imagecheck"]
