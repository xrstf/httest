# SPDX-FileCopyrightText: 2024 Christoph Mewes
# SPDX-License-Identifier: MIT

FROM golang:1.23-alpine AS builder

RUN apk add -U make git

WORKDIR /go/src/go.xrstf.de/httest
COPY . .
RUN make

FROM gcr.io/distroless/static-debian12:nonroot

ENTRYPOINT ["httest"]
COPY --from=builder /go/src/go.xrstf.de/httest/_build/ /usr/local/bin/
