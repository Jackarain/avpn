#!/usr/bin/env bash
#
# 本地端到端隧道性能测试 (Linux netns + veth + iperf3).
#
# 在两个网络命名空间之间建立 veth, 分别运行 avpn gateway/endpoint,
# 通过隧道跑 iperf3 上下行, 可选 netem 注入延迟/丢包, 用于对比不同
# FEC / MTU / 压缩配置的吞吐.
#
# 用法 (需要 root, 依赖 ip / tc / iperf3):
#   sudo ./tools/bench_tunnel.sh
#   sudo DS=8 PS=2 DUR=10 ./tools/bench_tunnel.sh
#   sudo DS=8 PS=4 LOSS=0.5% DELAY=20ms ./tools/bench_tunnel.sh
#
# 可配置环境变量:
#   AVPN       avpn 可执行文件 (默认 build/bin/avpn)
#   DS / PS    FEC data/parity shards (默认 8/4, DS=1 PS=0 关闭 FEC)
#   MTU        tun MTU (默认 1400)
#   DUR        iperf3 测试时长, 秒 (默认 8)
#   LOSS       netem 丢包率, 如 0.5% (默认不注入)
#   DELAY      netem 单向延迟, 如 20ms (默认不注入)
#   COMPRESS   压缩算法 deflate/lz4/zstd (默认关闭)
#   OBF        混淆密钥 (默认关闭)
#
set -u

AVPN=${AVPN:-build/bin/avpn}
DS=${DS:-8}
PS=${PS:-4}
MTU=${MTU:-1400}
DUR=${DUR:-8}
LOSS=${LOSS:-}
DELAY=${DELAY:-}
COMPRESS=${COMPRESS:-}
OBF=${OBF:-}

NS_GW=avpnbench-gw
NS_EP=avpnbench-ep
VETH_GW=192.168.77.1
VETH_EP=192.168.77.2
GW_TUN=10.10.0.1
EP_TUN=10.10.0.2

GW_PID=""
EP_PID=""

cleanup() {
	[ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null
	[ -n "$EP_PID" ] && kill "$EP_PID" 2>/dev/null
	ip netns del "$NS_GW" 2>/dev/null
	ip netns del "$NS_EP" 2>/dev/null
}
trap cleanup EXIT

if [ "$(id -u)" != "0" ]; then
	echo "需要 root 权限 (netns/veth/tun)" >&2
	exit 1
fi
if [ ! -x "$AVPN" ]; then
	echo "找不到 avpn 可执行文件: $AVPN" >&2
	exit 1
fi

cleanup
ip netns add "$NS_GW"
ip netns add "$NS_EP"
ip link add veth-gw type veth peer name veth-ep
ip link set veth-gw netns "$NS_GW"
ip link set veth-ep netns "$NS_EP"
ip netns exec "$NS_GW" ip addr add "$VETH_GW/24" dev veth-gw
ip netns exec "$NS_EP" ip addr add "$VETH_EP/24" dev veth-ep
ip netns exec "$NS_GW" ip link set veth-gw up
ip netns exec "$NS_EP" ip link set veth-ep up
ip netns exec "$NS_GW" ip link set lo up
ip netns exec "$NS_EP" ip link set lo up

NETEM=""
[ -n "$DELAY" ] && NETEM="$NETEM delay $DELAY"
[ -n "$LOSS" ] && NETEM="$NETEM loss $LOSS"
if [ -n "$NETEM" ]; then
	ip netns exec "$NS_GW" tc qdisc add dev veth-gw root netem $NETEM
	ip netns exec "$NS_EP" tc qdisc add dev veth-ep root netem $NETEM
fi

# 生成双方静态密钥对 (private/public 必须来自同一次 genkey).
KEY_GW=$("$AVPN" --genkey)
K_GW=$(echo "$KEY_GW" | awk '/private/{print $2}')
P_GW=$(echo "$KEY_GW" | awk '/public/{print $2}')
KEY_EP=$("$AVPN" --genkey)
K_EP=$(echo "$KEY_EP" | awk '/private/{print $2}')
P_EP=$(echo "$KEY_EP" | awk '/public/{print $2}')
if [ -z "$K_GW" ] || [ -z "$P_EP" ]; then
	echo "生成密钥失败" >&2
	exit 1
fi

COMP_OPT=""
[ -n "$COMPRESS" ] && COMP_OPT="--compress $COMPRESS"
OBF_OPT=""
[ -n "$OBF" ] && OBF_OPT="--obfuscate_key $OBF"

# gateway: 监听 veth 地址, 分配虚拟子网; endpoint: 连接 gateway.
ip netns exec "$NS_GW" "$AVPN" --ifdev tun0 \
	--private_key "$K_GW" --public_key "$P_GW" --pkl "$P_EP" \
	--subnet 10.10.0.0/16 --udp_listen "$VETH_GW:28888" \
	--data_shards "$DS" --parity_shards "$PS" --mtu_size "$MTU" \
	$COMP_OPT $OBF_OPT --disable_logs true >/dev/null 2>&1 &
GW_PID=$!

ip netns exec "$NS_EP" "$AVPN" --ifdev tun0 \
	--private_key "$K_EP" --public_key "$P_GW" \
	--nexthop "udp://$VETH_GW:28888" --mtu_size "$MTU" \
	$COMP_OPT $OBF_OPT --disable_logs true >/dev/null 2>&1 &
EP_PID=$!

# 等待握手完成 (endpoint 侧 tun 配置到虚拟地址).
for _ in $(seq 1 50); do
	ip netns exec "$NS_EP" ip -br addr show tun0 2>/dev/null \
		| grep -q "$EP_TUN" && break
	sleep 0.2
done
if ! ip netns exec "$NS_EP" ip -br addr show tun0 2>/dev/null | grep -q "$EP_TUN"; then
	echo "隧道未建立 (握手失败)" >&2
	exit 1
fi

ip netns exec "$NS_GW" iperf3 -s -B "$GW_TUN" -D >/dev/null 2>&1
sleep 1

echo "== FEC=$DS/$PS mtu=$MTU dur=${DUR}s loss='${LOSS:-0}' delay='${DELAY:-0}' compress='${COMPRESS:-none}'"
echo "-- upload (endpoint -> gateway)"
ip netns exec "$NS_EP" iperf3 -c "$GW_TUN" -t "$DUR" -f m -O 1 \
	| grep -E "sender|receiver"
echo "-- download (gateway -> endpoint)"
ip netns exec "$NS_EP" iperf3 -c "$GW_TUN" -t "$DUR" -f m -R -O 1 \
	| grep -E "sender|receiver"
