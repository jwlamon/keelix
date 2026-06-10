# Build a static keelix binary, then ship it on a minimal image.
FROM golang:1.26-alpine AS build
ARG VERSION=docker
WORKDIR /src
# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
	-ldflags "-s -w -X github.com/jakelamon/keelix/internal/version.Version=${VERSION}" \
	-o /out/keelix ./cmd/keelix

# Runtime: distroless static (includes CA certs for TLS probing + the AI API).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/keelix /usr/local/bin/keelix
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/keelix"]
CMD ["--help"]
