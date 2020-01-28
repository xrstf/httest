FROM golang:1.13-alpine as builder

WORKDIR /go/src/github.com/xrstf/httest
COPY . .
RUN go build -v -tags netgo -ldflags '-s -w' .

FROM alpine:3.11

WORKDIR /app
ENTRYPOINT ["./httest"]
COPY --from=builder /go/src/github.com/xrstf/httest/httest .
