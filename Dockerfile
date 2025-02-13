FROM golang:1.23.5-bookworm AS builder
RUN apt update && apt upgrade -y && apt install curl git make -y
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

FROM debian:bookworm-slim
RUN apt update && apt upgrade -y
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY --from=builder /app/bin/imagecheck /usr/local/bin/
RUN useradd -u 1001 -ms /bin/bash app
USER app
WORKDIR /home/app
USER 1001:1001
ENTRYPOINT ["/usr/local/bin/imagecheck"]
