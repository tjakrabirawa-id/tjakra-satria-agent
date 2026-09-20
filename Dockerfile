# Multi-stage build for the tjakra-satria patrol agent.
# Stage 1 builds a static binary. Stage 2 is a small alpine image with iptables
# and ca-certificates, for the shared network-namespace enforcement pattern
# (see docs/DEPLOYMENT.md).

FROM golang:1.23-alpine AS build
WORKDIR /src
# Copy the module files first so the layer caches when only source changes.
COPY go.mod ./
RUN go mod download
COPY . .
# CGO off produces a static binary that runs on the alpine base without libc.
RUN CGO_ENABLED=0 go build -trimpath -o /out/tjakra-satria-agent .

FROM alpine:3.20
RUN apk add --no-cache iptables ca-certificates
COPY --from=build /out/tjakra-satria-agent /usr/local/bin/tjakra-satria-agent
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
# The enrolled config lives on a data volume so it survives container replacement
# and is never part of an image layer. Enforcing block_ip and revert_block needs
# NET_ADMIN, granted at docker run.
VOLUME ["/data"]
# A bare `docker run` reads SERVER + ENROLL_TOKEN from the environment, enrolls on
# first boot, and runs (see docker-entrypoint.sh). An explicit `enroll`/`run`
# subcommand still runs the binary directly.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
