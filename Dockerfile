FROM golang:1.23.4 AS builder

WORKDIR /app/src

COPY . .

RUN CGO_ENABLED=0 go build -o /app/bin/ ./cmd/...

FROM scratch

WORKDIR /app

COPY --from=builder /app/bin .

ENTRYPOINT ["/app/dcdn"]
