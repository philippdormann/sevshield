# syntax=docker/dockerfile:1

# ---- Web UI (SvelteKit static, arch-independent) ----
FROM --platform=$BUILDPLATFORM oven/bun:1-alpine@sha256:629e17411f1f129dbec3af78d5af9c9f2a937435c80349437206c6b0b7422373 AS web
WORKDIR /web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun run build

# ---- Backend (static Go binary, no CGO) ----
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS backend
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/build ./web/build
ARG TARGETARCH
RUN mkdir -p /out/data && \
    CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -o /out/sevshield ./cmd/sevshield

# ---- Runtime: scratch + CA certs + nonroot ----
FROM scratch
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=backend /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=backend --chown=65532:65532 /out/data /data
COPY --from=backend /out/sevshield /app/sevshield
# SQLite default; set DATABASE_URL at runtime to use Postgres instead
# (DATABASE_PATH is then ignored).
ENV PORT=8080 DATABASE_PATH=/data/sevshield.db
VOLUME /data
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app/sevshield"]
