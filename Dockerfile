# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
# Static binary without cgo; the target platform comes from buildx (amd64 / arm64).
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/office-smtprelay ./cmd/office-smtprelay \
 && mkdir /out/data

# ---- runtime ----------------------------------------------------------------
# Distroless: no shell, no package manager, runs as a non-root user (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/office-smtprelay /office-smtprelay
COPY --from=build --chown=65532:65532 /out/data /data
ENV SMTPRELAY_DATA_DIR=/data
# 2525 = SMTP (map host port 587 to it), 8080 = web UI (plain HTTP, put an HTTPS reverse proxy in front)
EXPOSE 2525 8080
VOLUME /data
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/office-smtprelay", "healthcheck"]
ENTRYPOINT ["/office-smtprelay"]
