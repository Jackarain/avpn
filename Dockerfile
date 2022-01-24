FROM golang:1.14-alpine as builder

RUN apk add --no-cache make gcc musl-dev cmake ninja g++ linux-headers git

ADD . /avpn

RUN cd /avpn && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja && ninja

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /avpn/build/bin/avpn /usr/local/bin/

EXPOSE 33333 33333/udp

ENTRYPOINT ["avpn", --identity", "server", "--tun", "tun9", "--tcp", "\"[::]:33333\"", "--udp", "\"[::]:33333\"", "--fec_timeout", "1", "--data_shards", "1", "--parity_shards", "0", "--direct_tcp", "0"]

