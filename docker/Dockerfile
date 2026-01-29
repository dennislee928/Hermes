# Stage 1: build
FROM golang:1.21-alpine AS builder
WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/hermes ./cmd/server

# Stage 2: runtime
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
RUN adduser -D -g '' appuser

WORKDIR /app
COPY --from=builder /app/hermes .

USER appuser
EXPOSE 8080
ENTRYPOINT ["/app/hermes"]
