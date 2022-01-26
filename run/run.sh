#!/bin/bash
cd  /usr/local/bin/
./avpn --identity server --tun tun9 --tcp [::]:$TCP_PORT --udp [::]:$UDP_PORT --fec_timeout $FEC_TIMEOUT --data_shards $DATA_SHARDS --parity_shards $PARITY_SHARDS --direct_tcp $DIRECT_TCP
