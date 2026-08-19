import { useEffect, useState } from "react";
import { useApp } from "@/store/app";
import { api } from "@/lib/api";
import { fmtBytes, fmtDur, fmtRate } from "@/lib/format";
import type { SessionInfo, StatusData, StatusReport } from "@/lib/types";

// 状态摘要条（横向单行，可换行）。
function StatsBar({ report }: { report: StatusReport | null }) {
  const r = report;
  return (
    <div className="mb-4 flex flex-wrap items-baseline gap-x-6 gap-y-1 border border-border bg-card px-4 py-2.5 text-[13px]">
      <div className="flex items-baseline gap-1.5 whitespace-nowrap">
        <span className="text-xs text-muted-foreground">模式</span>
        <span className="num font-semibold">
          {r?.mode === "client" ? "客户端" : "网关"}
        </span>
      </div>
      <div className="flex items-baseline gap-1.5 whitespace-nowrap">
        <span className="text-xs text-muted-foreground">运行</span>
        <span className="num font-semibold">{fmtDur(r?.uptime)}</span>
      </div>
      <div className="flex items-baseline gap-1.5 whitespace-nowrap">
        <span className="text-xs text-muted-foreground">活跃会话</span>
        <span className="num font-semibold text-primary">
          {r?.active_connections ?? 0}
        </span>
      </div>
      <div className="flex items-baseline gap-1.5 whitespace-nowrap">
        <span className="text-xs text-ok">▲</span>
        <span className="num font-semibold text-ok">
          {fmtRate(r?.rates?.rx_rate_bps)}
        </span>
      </div>
      <div className="flex items-baseline gap-1.5 whitespace-nowrap">
        <span className="text-xs text-warn">▼</span>
        <span className="num font-semibold text-warn">
          {fmtRate(r?.rates?.tx_rate_bps)}
        </span>
      </div>
      <div className="flex items-baseline gap-1.5 whitespace-nowrap">
        <span className="text-xs text-muted-foreground">上传</span>
        <span className="num font-semibold opacity-75">
          {fmtBytes(r?.global?.rx_bytes)}
        </span>
      </div>
      <div className="flex items-baseline gap-1.5 whitespace-nowrap">
        <span className="text-xs text-muted-foreground">下载</span>
        <span className="num font-semibold opacity-75">
          {fmtBytes(r?.global?.tx_bytes)}
        </span>
      </div>
    </div>
  );
}

// 会话明细表（按对端排序展示）。
function SessionTable({ sessions }: { sessions: SessionInfo[] }) {
  if (!sessions.length) {
    return (
      <table className="w-full border-separate border-spacing-0 border border-border bg-card">
        <tbody>
          <tr>
            <td className="px-3 py-7 text-center text-muted-foreground">
              暂无会话
            </td>
          </tr>
        </tbody>
      </table>
    );
  }

  return (
    <table className="w-full border-separate border-spacing-0 border border-border bg-card">
      <thead>
        <tr>
          {["虚拟地址", "对端", "远端地址", "传输", "状态", "上行速率", "下行速率", "累计上传", "累计下载"].map(
            (h, i) => (
              <th
                key={h}
                className={`whitespace-nowrap bg-secondary px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted-foreground ${
                  i > 0 ? "num" : ""
                }`}
              >
                {h}
              </th>
            )
          )}
        </tr>
      </thead>
      <tbody>
        {sessions.map((s, i) => (
          <tr
            key={s.vaddr || i}
            className={`border-t border-border ${i % 2 ? "bg-primary/5" : ""}`}
          >
            <td className="px-3 py-2 font-mono">{s.vaddr}</td>
            <td className="px-3 py-2 font-mono">{s.peer || "—"}</td>
            <td className="px-3 py-2 font-mono">{s.remote || "—"}</td>
            <td className="px-3 py-2 uppercase">{s.transport}</td>
            <td className="px-3 py-2">
              <span
                className={`font-semibold ${
                  s.established ? "text-ok" : "text-warn"
                }`}
              >
                {s.established ? "已连接" : "握手中"}
              </span>
            </td>
            <td className="num px-3 py-2 text-ok">{fmtRate(s.rx_rate_bps)}</td>
            <td className="num px-3 py-2 text-warn">{fmtRate(s.tx_rate_bps)}</td>
            <td className="num px-3 py-2">{fmtBytes(s.rx_bytes)}</td>
            <td className="num px-3 py-2">{fmtBytes(s.tx_bytes)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function StatusTab({ id, active }: { id: string; active: boolean }) {
  const [report, setReport] = useState<StatusReport | null>(null);
  const tick = useApp((s) => s.tick);

  // 2 秒轮询刷新状态（仅活跃页签）。
  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    (async () => {
      try {
        const s = await api<StatusData>(`/api/instances/${id}/status`);
        if (cancelled || useApp.getState().curId !== id) return; // 竞态防护
        setReport(s.report || null);
      } catch {
        /* 静默，等下一轮 */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [active, id, tick]);

  return (
    <div>
      <StatsBar report={report} />
      <div className="mb-2 mt-1 text-[13px] font-semibold text-muted-foreground">
        会话
      </div>
      <SessionTable sessions={report?.sessions || []} />
    </div>
  );
}
