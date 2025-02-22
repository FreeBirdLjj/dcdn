FROM golang:1.24 AS builder

WORKDIR /app/src

RUN --mount=type=bind,target=. \
    CGO_ENABLED=0 go build -o /app/bin/ ./cmd/...

FROM scratch

WORKDIR /app

COPY --from=builder /app/bin .

ENTRYPOINT ["/app/dcdn"]
