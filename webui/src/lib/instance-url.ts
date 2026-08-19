import { useApp } from "@/store/app";
import { firstConnectAddr } from "@/lib/listen";
import { copyText } from "@/lib/copy";
import { api } from "@/lib/api";
import { showToast } from "@/lib/toast";
import type { InstanceDetail } from "@/lib/types";

// 一键复制实例对外连接地址（nexthop 或监听地址）。
export async function copyInstanceURL(id: string) {
  let inst: InstanceDetail;
  try {
    inst = await api<InstanceDetail>(`/api/instances/${id}`);
  } catch (e) {
    showToast((e as Error).message, "err");
    return;
  }
  if (useApp.getState().curId !== id) return; // 已切换实例，丢弃过期结果
  const cfg = inst.config || {};

  const addr = firstConnectAddr(cfg);
  if (!addr) {
    showToast("实例未配置 nexthop 或监听地址", "warn");
    return;
  }

  const host = window.location.hostname || "127.0.0.1";
  // 复制到本机可达形式：地址不含本机地址时按 launcher 所在主机补全。
  let url = addr;
  if (/^0\.0\.0\.0$|^\[?::\]?$|^\*$/.test(addr.split(":")[0])) {
    const port = addr.lastIndexOf(":");
    url = port > 0 ? `${host}${addr.slice(port)}` : addr;
  }

  const ok = await copyText(url);
  showToast(ok ? `已复制地址: ${url}` : `复制失败，请手动复制: ${url}`, ok ? "ok" : "warn");
}
