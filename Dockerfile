FROM alpine:edge as builder

RUN apk add --no-cache fortify-headers bsd-compat-headers libgphobos libgomp libatomic binutils bash build-base make gcc musl-dev cmake ninja g++ linux-headers git bison elfutils-dev libax25-dev libcap-dev flex iptables-dev

ADD . /avpn

RUN cd /avpn && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXE_LINKER_FLAGS="-static" -G Ninja && ninja

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /avpn/build/bin/avpn /usr/local/bin/

EXPOSE 33333 33333/udp

ENTRYPOINT ["avpn", "--identity", "server", "--tun", "tun9", "--tcp", "[::]:33333", "--udp", "[::]:33333", "--fec_timeout", "1", "--data_shards", "1", "--parity_shards", "0", "--direct_tcp", "0"]

