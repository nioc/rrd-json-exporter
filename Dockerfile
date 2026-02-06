ARG GO_VERSION=1.25


### Create base image ###
FROM alpine:3.23 AS base
RUN addgroup -S rrd && adduser -S rrd -G rrd \
  && apk add --no-cache rrdtool


### Compile Go binary ##
FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GIT_COMMIT=unspecified
ARG BUILD_DATE
ARG VERSION=unspecified
RUN CGO_ENABLED=0 GOOS=linux go build \
  -trimpath \
  -ldflags "-s -w \
  -X main.Version=$VERSION \
  -X main.Commit=$GIT_COMMIT \
  -X main.BuildDate=$BUILD_DATE" \
  -o rrd-json-exporter .


### Copy binary in base image ###
FROM base
WORKDIR /app
COPY --from=builder /app/rrd-json-exporter .

USER rrd

VOLUME ["/app/rrd"]

ENV PORT=8080
ENV LOG_LEVEL=info
ENV CACHE_TTL_LIST=1800
ENV CACHE_TTL_METRICS=60
ENV ROUND_STEP=300

EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

ARG GIT_COMMIT=unspecified
ARG BUILD_DATE
ARG VERSION=unspecified
LABEL org.label-schema.name="rrd-json-exporter"
LABEL org.label-schema.vendor="nioc"
LABEL org.label-schema.license="GPL-3.0-or-later"
LABEL org.label-schema.vcs-url="https://github.com/nioc/rrd-json-exporter"
LABEL org.label-schema.vcs-ref=$GIT_COMMIT
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.version=$VERSION
LABEL maintainer="nioc <dev@nioc.eu>"

CMD ["./rrd-json-exporter"]
