FROM golang:1.24 AS builder

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/web ./cmd/web

FROM gcr.io/distroless/static-debian12

COPY --from=builder /go/bin/web /
CMD /web -port $PORT