// 取实例对外连接地址：客户端取 nexthop，网关取第一个 tcp/udp 监听地址。
export function firstConnectAddr(cfg: Record<string, unknown>): string {
  const nh = String(cfg.nexthop || "").trim();
  if (nh) return nh;
  for (const key of ["tcp_listen", "udp_listen"]) {
    const list = cfg[key];
    if (Array.isArray(list)) {
      for (const raw of list) {
        const s = String(raw).trim();
        if (s) return s;
      }
    }
  }
  return "";
}
