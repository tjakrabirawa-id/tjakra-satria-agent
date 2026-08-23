# Multi-stage build for the tjakra-ap patrol agent.
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
RUN CGO_ENABLED=0 go build -trimpath -o /out/tjakra-ap-agent .

FROM alpine:3.20
RUN apk add --no-cache iptables ca-certificates
COPY --from=build /out/tjakra-ap-agent /usr/local/bin/tjakra-ap-agent
# The config is provided at run time by bind-mounting an enrolled agent.json.
# Enforcing block_ip and revert_block needs NET_ADMIN, granted at docker run.
ENTRYPOINT ["/usr/local/bin/tjakra-ap-agent"]
CMD ["run", "-config", "/agent.json"]
