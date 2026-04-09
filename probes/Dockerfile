# Build stage: compile the Go binary.
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /probe .


# Runtime stage: minimal Alpine with libpcap only.
FROM alpine:3.19

RUN apk add --no-cache libpcap ca-certificates

COPY --from=builder /probe /usr/local/bin/probe

ENTRYPOINT ["/usr/local/bin/probe"]
