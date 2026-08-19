// 后端 REST API 数据契约（与 launcher WebUI 一致）。

export interface InstanceSummary {
  id: string;
  name: string;
  state: string;
  online: boolean;
  pid?: number;
  autostart: boolean;
  listen: string[];
  active: number;
  rx_rate_bps: number;
  tx_rate_bps: number;
}

export interface OptionDef {
  name: string;
  kind: "bool" | "int" | "string" | "stringlist";
  category: string;
  help: string;
  hint?: string;
  default?: unknown;
  restart_only?: boolean;
  common?: boolean;
}

// avpn 会话（对端）信息。
export interface SessionInfo {
  vaddr: string;
  established: boolean;
  transport: string;
  peer?: string;
  remote?: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_rate_bps: number;
  tx_rate_bps: number;
}

export interface StatusReport {
  ts: number;
  started_at?: number;
  uptime: number;
  mode?: "gateway" | "client";
  active_connections: number;
  global?: { rx_bytes: number; tx_bytes: number };
  rates?: { rx_rate_bps: number; tx_rate_bps: number };
  sessions?: SessionInfo[];
}

export interface StatusData {
  online: boolean;
  state: string;
  pid?: number;
  last_seen?: string;
  report?: StatusReport;
}

export interface InstanceDetail {
  id: string;
  name: string;
  state: string;
  online: boolean;
  pid?: number;
  autostart: boolean;
  config: Record<string, unknown>;
  created_at?: string;
}

export interface LogLine {
  seq: number;
  text: string;
}

export interface LogData {
  lines: string[];
  seqs?: number[];
  next: number;
  gen: number;
}

export interface ApplyResult {
  applied?: string[];
  needs_restart?: string[];
  errors?: Record<string, string>;
}
