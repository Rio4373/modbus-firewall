import React from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  FileCheck2,
  FileCog,
  Gauge,
  History,
  ListFilter,
  Network,
  RefreshCw,
  Save,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  TerminalSquare,
  XCircle,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:18080";

type StatusPayload = {
  status: string;
  mode: string;
  raw_mode: string;
  pid: number;
  uptime_sec: number;
  active_policy: string;
  active_policy_id: string;
  policy_version: number;
  policy_rules: number;
  last_policy_apply_time: string | null;
  active_connections: number;
  connection_losses: number;
};

type TrafficEvent = {
  id: number;
  timestamp: string;
  mode: string;
  source_ip: string;
  destination_ip: string;
  unit_id: number;
  function_code: number;
  start_address: number;
  quantity: number;
  result: "ALLOW" | "BLOCK" | string;
  reason?: string;
  latency_ms: number;
  meta?: Record<string, string>;
};

type SystemEvent = {
  id: number;
  timestamp: string;
  type: string;
  severity: string;
  message: string;
  fields?: Record<string, string>;
};

type MetricsPayload = {
  processed_requests: number;
  allowed_requests: number;
  blocked_requests: number;
  errors: number;
  connection_losses: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  requests_sec: number;
  blocked_sec: number;
  active_connections: number;
  traffic: TrafficEvent[];
};

type AddressRange = { start: number; end: number };
type PolicyRule = {
  id: string;
  action: string;
  source_ips: string[];
  destination_ips: string[];
  unit_ids: number[];
  function_codes: number[];
  address_ranges: AddressRange[];
};
type PolicyDTO = {
  version: number;
  default_action: string;
  rules: PolicyRule[];
};
type PolicyMetadata = {
  id: string;
  name: string;
  path: string;
  active: boolean;
  version: number;
  default_action: string;
  rule_count: number;
  created_at: string;
  updated_at: string;
  validation_status: string;
  error?: string;
};
type PolicyDetail = {
  metadata: PolicyMetadata;
  raw: string;
  policy: PolicyDTO;
};
type GenerationSummary = {
  events_processed: number;
  groups_created: number;
  read_rules: number;
  write_rules: number;
  ranges_merged: number;
  write_operations_excluded: number;
  rules_total: number;
  write_threshold: number;
};
type VerificationReport = {
  policy_id: string;
  total_historical_requests: number;
  total_observed_requests?: number;
  allowed_by_policy: number;
  blocked_by_policy: number;
  uncovered_historical_requests: number;
  excluded_forbidden_requests?: number;
  false_positive: number;
  normal_traffic_coverage: number;
  requires_attention: Array<Record<string, unknown>>;
};

type ChartPoint = {
  time: string;
  разрешено: number;
  заблокировано: number;
  задержка: number;
};

type ConfirmRequest = {
  title: string;
  message: string;
  confirmLabel: string;
  tone?: "default" | "warning" | "danger";
  resolve: (confirmed: boolean) => void;
};

const navItems = [
  { id: "overview", label: "Обзор", icon: Gauge },
  { id: "traffic", label: "Трафик", icon: Network },
  { id: "policies", label: "Политики", icon: ShieldCheck },
  { id: "generation", label: "Формирование политики", icon: FileCog },
  { id: "verification", label: "Верификация", icon: FileCheck2 },
  { id: "logs", label: "Журналы", icon: TerminalSquare },
  { id: "settings", label: "Настройки", icon: Settings },
] as const;

type PageID = (typeof navItems)[number]["id"];
type PolicyID = "candidate" | "active";

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json() as Promise<T>;
}

function formatNumber(value?: number, digits = 0) {
  return new Intl.NumberFormat("ru-RU", {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  }).format(Number(value || 0));
}

function formatDate(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  if (date.getUTCFullYear() <= 1) return "-";
  return date.toLocaleString("ru-RU", { hour12: false });
}

function formatTime(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleTimeString("ru-RU", { hour12: false });
}

function formatUptime(seconds?: number) {
  const sec = Number(seconds || 0);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return `${h} ч ${m} мин ${s} с`;
  if (m > 0) return `${m} мин ${s} с`;
  return `${s} с`;
}

function modeLabel(mode?: string) {
  const normalized = String(mode || "").toUpperCase();
  return normalized === "FILTER" || normalized === "ENFORCE" ? "фильтрация" : "наблюдение";
}

function policyActionLabel(action?: string) {
  switch (action) {
    case "allow":
      return "разрешить";
    case "deny":
      return "запрет";
    default:
      return action || "-";
  }
}

function eventTypeLabel(type?: string) {
  switch (type) {
    case "policy_generated":
      return "политика сформирована";
    case "policy_verified":
      return "политика проверена";
    case "policy_applied":
      return "политика применена";
    case "policy_reload":
      return "политика перечитана";
    case "mode_changed":
      return "режим изменен";
    case "blocked_request":
      return "запрос заблокирован";
    case "error":
      return "ошибка";
    default:
      return type || "-";
  }
}

function severityLabel(severity?: string) {
  switch (severity) {
    case "ERROR":
      return "ошибка";
    case "WARN":
      return "внимание";
    case "INFO":
      return "инфо";
    default:
      return severity || "-";
  }
}

function reasonLabel(reason?: string) {
  switch (reason) {
    case "policy decision deny":
      return "запрещено политикой";
    case "policy decision allow":
      return "разрешено политикой";
    case "invalid request":
      return "некорректный запрос";
    default:
      return reason || "соответствует политике";
  }
}

function eventMessageLabel(message?: string) {
  switch (message) {
    case "hot reload успешно применен":
      return "правила перечитаны без перезапуска";
    case "политика применена без остановки службы":
    case "политика проверена на исторических событиях":
    case "сформирована новая разрешающая политика":
      return message;
    default:
      return message || "-";
  }
}

function delay(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function App() {
  const [page, setPage] = React.useState<PageID>("overview");
  const [status, setStatus] = React.useState<StatusPayload | null>(null);
  const [metrics, setMetrics] = React.useState<MetricsPayload | null>(null);
  const [traffic, setTraffic] = React.useState<TrafficEvent[]>([]);
  const [events, setEvents] = React.useState<SystemEvent[]>([]);
  const [policies, setPolicies] = React.useState<PolicyMetadata[]>([]);
  const [activePolicy, setActivePolicy] = React.useState<PolicyDetail | null>(null);
  const [candidatePolicy, setCandidatePolicy] = React.useState<PolicyDetail | null>(null);
  const [chartData, setChartData] = React.useState<ChartPoint[]>([]);
  const [error, setError] = React.useState<string>("");
  const [notice, setNotice] = React.useState<string>("");
  const [busy, setBusy] = React.useState<string>("");
  const [confirmRequest, setConfirmRequest] = React.useState<ConfirmRequest | null>(null);
  const [writeThreshold, setWriteThreshold] = React.useState(1);
  const [generationSummary, setGenerationSummary] = React.useState<GenerationSummary | null>(null);
  const [verification, setVerification] = React.useState<VerificationReport | null>(null);
  const [verificationTarget, setVerificationTarget] = React.useState<PolicyID>("candidate");
  const [applyResult, setApplyResult] = React.useState<Record<string, unknown> | null>(null);

  const refresh = React.useCallback(async () => {
    try {
      const [nextStatus, nextMetrics, policyList, active, candidate, logs] = await Promise.all([
        api<StatusPayload>("/api/status"),
        api<MetricsPayload>("/api/metrics"),
        api<{ items: PolicyMetadata[] }>("/api/policies"),
        api<PolicyDetail>("/api/policies/active").catch(() => null),
        api<PolicyDetail>("/api/policies/candidate").catch(() => null),
        api<{ system: SystemEvent[]; traffic: TrafficEvent[] }>("/api/logs"),
      ]);
      setStatus(nextStatus);
      setMetrics(nextMetrics);
      setTraffic(nextMetrics.traffic || []);
      setPolicies(policyList.items || []);
      setActivePolicy(active);
      setCandidatePolicy(candidate);
      setEvents(logs.system || []);
      setError("");
      setChartData((prev) => {
        const point = {
          time: new Date().toLocaleTimeString("ru-RU", { hour12: false }),
          разрешено: nextMetrics.allowed_requests || 0,
          заблокировано: nextMetrics.blocked_requests || 0,
          задержка: nextMetrics.avg_latency_ms || 0,
        };
        return [...prev.slice(-39), point];
      });
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : "API недоступен");
    }
  }, []);

  React.useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 5000);
    const stream = new EventSource(`${API_BASE}/api/stream`);
    stream.addEventListener("update", (event) => {
      const data = JSON.parse(event.data);
      if (data.traffic) setTraffic(data.traffic);
      if (data.events) setEvents(data.events);
    });
    stream.onerror = () => setError("Поток событий недоступен");
    return () => {
      window.clearInterval(timer);
      stream.close();
    };
  }, [refresh]);

  const requestConfirmation = React.useCallback((request: Omit<ConfirmRequest, "resolve">) => {
    return new Promise<boolean>((resolve) => {
      setConfirmRequest({ ...request, resolve });
    });
  }, []);

  function resolveConfirmation(confirmed: boolean) {
    if (confirmRequest) {
      confirmRequest.resolve(confirmed);
      setConfirmRequest(null);
    }
  }

  async function runAction<T>(name: string, action: () => Promise<T>, options: { settleMs?: number; success?: string } = {}) {
    setBusy(name);
    setError("");
    setNotice("");
    try {
      const result = await action();
      await refresh();
      if (options.settleMs) {
        await delay(options.settleMs);
        await refresh();
      }
      if (options.success) {
        setNotice(options.success);
      }
      return result;
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : "Операция не выполнена");
      return null;
    } finally {
      setBusy("");
    }
  }

  async function setMode(mode: "ANALYZE" | "FILTER") {
    if (status?.mode === mode) {
      setNotice(`Режим уже установлен: ${modeLabel(mode)}`);
      return;
    }
    const confirmed = await requestConfirmation({
      title: mode === "FILTER" ? "Включить фильтрацию" : "Включить наблюдение",
      message:
        mode === "FILTER"
          ? "Новые Modbus TCP запросы будут проверяться по активной политике. Несоответствующие операции будут блокироваться."
          : "Трафик будет проходить без блокировки. События продолжат накапливаться для формирования политики.",
      confirmLabel: mode === "FILTER" ? "Включить фильтрацию" : "Включить наблюдение",
      tone: mode === "FILTER" ? "danger" : "warning",
    });
    if (!confirmed) return;
    await runAction(
      "mode",
      () => api("/api/mode", { method: "POST", body: JSON.stringify({ mode }) }),
      { settleMs: 1600, success: `Режим изменен: ${modeLabel(mode)}` },
    );
  }

  async function generatePolicy() {
    const result = await runAction(
      "generate",
      () =>
        api<{ summary: GenerationSummary }>("/api/policies/generate", {
          method: "POST",
          body: JSON.stringify({ write_threshold: writeThreshold }),
        }),
      { success: "Кандидат политики сформирован по историческим событиям" },
    );
    if (result) setGenerationSummary(result.summary);
  }

  async function verifyPolicy(id: PolicyID = "candidate") {
    const confirmed = await requestConfirmation({
      title: id === "active" ? "Проверить активную политику" : "Проверить кандидата политики",
      message:
        id === "active"
          ? "Активная политика будет проверена на исторических событиях. Непокрытые операции будут вынесены в список для анализа."
          : "Кандидат политики будет проверен на исторических событиях перед применением.",
      confirmLabel: "Запустить проверку",
      tone: "warning",
    });
    if (!confirmed) return;
    setVerificationTarget(id);
    const result = await runAction(
      "verify",
      () => api<VerificationReport>(`/api/policies/${id}/verify`, { method: "POST", body: "{}" }),
      { success: `Проверка ${id === "active" ? "активной политики" : "кандидата политики"} завершена` },
    );
    if (result) setVerification(result);
  }

  async function applyPolicy(id = "candidate") {
    const confirmed = await requestConfirmation({
      title: id === "candidate" ? "Утвердить кандидата политики" : "Активная политика уже утверждена",
      message:
        id === "candidate"
          ? "После approve кандидат станет единственной активной политикой, а candidate policy будет удалена из списка."
          : "Повторное применение active policy недоступно: рабочая политика меняется только через нового кандидата и approve.",
      confirmLabel: id === "candidate" ? "Утвердить" : "Закрыть",
      tone: "danger",
    });
    if (!confirmed || id !== "candidate") return;
    const result = await runAction(
      "apply",
      () => api<Record<string, unknown>>(`/api/policies/${id}/apply`, { method: "POST", body: "{}" }),
      { settleMs: 1600, success: "Кандидат утвержден как активная политика" },
    );
    if (result) setApplyResult(result);
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-border bg-[#08121d] px-4 py-5 lg:block">
        <div className="mb-7 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md border border-success/60 bg-success/10">
            <Shield className="h-5 w-5 text-success" />
          </div>
          <div>
            <div className="text-base font-semibold">Межсетевой экран Modbus TCP</div>
            <div className="text-xs text-muted">инженерная консоль</div>
          </div>
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={`nav-button ${page === item.id ? "nav-button-active" : ""}`}
                onClick={() => setPage(item.id)}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="absolute bottom-5 left-4 right-4 rounded-md border border-border bg-card p-3 text-sm">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-muted">API</span>
            <StatusBadge tone={error ? "danger" : "success"}>{error ? "недоступен" : "подключен"}</StatusBadge>
          </div>
          <div className="truncate text-xs text-muted">{API_BASE}</div>
        </div>
      </aside>

      <main className="lg:pl-72">
        <header className="sticky top-0 z-10 border-b border-border bg-background/95 px-5 py-4 backdrop-blur">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <h1 className="text-xl font-semibold">{navItems.find((item) => item.id === page)?.label}</h1>
              <p className="text-sm text-muted">Контроль, политика, верификация и журналы межсетевого экрана Modbus TCP.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="secondary" onClick={refresh} disabled={Boolean(busy)}>
                <RefreshCw className="h-4 w-4" /> Обновить
              </Button>
              <Button variant={status?.mode === "ANALYZE" ? "warning" : "secondary"} onClick={() => setMode("ANALYZE")} disabled={busy === "mode"}>
                <Activity className="h-4 w-4" /> Наблюдение
              </Button>
              <Button variant={status?.mode === "FILTER" ? "primary" : "secondary"} onClick={() => setMode("FILTER")} disabled={busy === "mode" || !status?.active_policy}>
                <ShieldCheck className="h-4 w-4" /> Фильтрация
              </Button>
            </div>
          </div>
          {error ? <div className="mt-3 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-red-200">{error}</div> : null}
          {notice ? <div className="mt-3 rounded-md border border-success/40 bg-success/10 px-3 py-2 text-sm text-green-100">{notice}</div> : null}
        </header>

        <div className="p-5">
          {page === "overview" && (
            <OverviewPage
              status={status}
              metrics={metrics}
              chartData={chartData}
              events={events}
            />
          )}
          {page === "traffic" && <TrafficPage traffic={traffic} />}
          {page === "policies" && (
            <PoliciesPage
              policies={policies}
              activePolicy={activePolicy}
              candidatePolicy={candidatePolicy}
              applyResult={applyResult}
              onApply={applyPolicy}
              busy={busy}
            />
          )}
          {page === "generation" && (
            <GenerationPage
              writeThreshold={writeThreshold}
              onWriteThresholdChange={setWriteThreshold}
              onGenerate={generatePolicy}
              summary={generationSummary}
              candidatePolicy={candidatePolicy}
              busy={busy}
            />
          )}
          {page === "verification" && (
            <VerificationPage
              report={verification}
              selectedPolicy={verificationTarget}
              hasActivePolicy={Boolean(activePolicy)}
              onVerify={verifyPolicy}
              busy={busy}
            />
          )}
          {page === "logs" && <LogsPage events={events} traffic={traffic} />}
          {page === "settings" && <SettingsPage apiBase={API_BASE} status={status} />}
        </div>
      </main>
      <ConfirmDialog request={confirmRequest} onResolve={resolveConfirmation} />
    </div>
  );
}

function OverviewPage({
  status,
  metrics,
  chartData,
  events,
}: {
  status: StatusPayload | null;
  metrics: MetricsPayload | null;
  chartData: ChartPoint[];
  events: SystemEvent[];
}) {
  return (
    <div className="space-y-5">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Kpi title="Состояние службы" value={status?.status === "online" ? "работает" : "недоступна"} tone={status?.status === "online" ? "success" : "danger"} />
        <Kpi title="Текущий режим" value={modeLabel(status?.mode)} tone={status?.mode === "FILTER" ? "success" : "warning"} />
        <Kpi title="Активная политика" value={status?.active_policy || "отсутствует"} tone={status?.active_policy ? "success" : "warning"} />
        <Kpi title="Версия политики" value={String(status?.policy_version || 0)} />
        <Kpi title="Последнее применение" value={formatDate(status?.last_policy_apply_time)} />
        <Kpi title="PID процесса" value={String(status?.pid || "-")} />
        <Kpi title="Время работы" value={formatUptime(status?.uptime_sec)} />
        <Kpi title="Активные соединения" value={formatNumber(status?.active_connections)} />
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Kpi title="Обработано запросов" value={formatNumber(metrics?.processed_requests)} />
        <Kpi title="Разрешено" value={formatNumber(metrics?.allowed_requests)} tone="success" />
        <Kpi title="Заблокировано" value={formatNumber(metrics?.blocked_requests)} tone="danger" />
        <Kpi title="Ошибки обработки" value={formatNumber(metrics?.errors)} tone={metrics?.errors ? "danger" : "default"} />
        <Kpi title="Потери соединений" value={formatNumber(metrics?.connection_losses)} tone={metrics?.connection_losses ? "danger" : "success"} />
        <Kpi title="Средняя задержка" value={`${formatNumber(metrics?.avg_latency_ms, 2)} мс`} />
        <Kpi title="P95" value={`${formatNumber(metrics?.p95_latency_ms, 2)} мс`} />
        <Kpi title="P99" value={`${formatNumber(metrics?.p99_latency_ms, 2)} мс`} />
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Разрешенные и заблокированные запросы" icon={Activity}>
          <ChartFrame>
            <AreaChart data={chartData}>
              <CartesianGrid stroke="#203044" />
              <XAxis dataKey="time" stroke="#8b9bad" />
              <YAxis stroke="#8b9bad" />
              <Tooltip contentStyle={{ background: "#0d1722", border: "1px solid #263445" }} />
              <Area dataKey="разрешено" stroke="#2cc36b" fill="#2cc36b33" />
              <Area dataKey="заблокировано" stroke="#ef4444" fill="#ef444433" />
            </AreaChart>
          </ChartFrame>
        </Panel>
        <Panel title="Задержка обработки" icon={Gauge}>
          <ChartFrame>
            <LineChart data={chartData}>
              <CartesianGrid stroke="#203044" />
              <XAxis dataKey="time" stroke="#8b9bad" />
              <YAxis stroke="#8b9bad" />
              <Tooltip contentStyle={{ background: "#0d1722", border: "1px solid #263445" }} />
              <Line type="monotone" dataKey="задержка" stroke="#38bdf8" strokeWidth={2} dot={false} />
            </LineChart>
          </ChartFrame>
        </Panel>
      </div>

      <Panel title="Последние события" icon={History}>
        <EventList events={events.slice(-8).reverse()} />
      </Panel>
    </div>
  );
}

function TrafficPage({ traffic }: { traffic: TrafficEvent[] }) {
  const [filters, setFilters] = React.useState({
    source: "",
    destination: "",
    fc: "",
    unit: "",
    action: "",
    addressFrom: "",
    addressTo: "",
  });

  const rows = traffic
    .filter((row) => !filters.source || row.source_ip.includes(filters.source))
    .filter((row) => !filters.destination || row.destination_ip.includes(filters.destination))
    .filter((row) => !filters.fc || String(row.function_code) === filters.fc)
    .filter((row) => !filters.unit || String(row.unit_id) === filters.unit)
    .filter((row) => !filters.action || row.result === filters.action)
    .filter((row) => !filters.addressFrom || row.start_address >= Number(filters.addressFrom))
    .filter((row) => !filters.addressTo || row.start_address <= Number(filters.addressTo))
    .slice(-200)
    .reverse();

  return (
    <Panel title="Modbus TCP события" icon={ListFilter}>
      <div className="mb-4 grid gap-3 md:grid-cols-3 xl:grid-cols-7">
        <Input placeholder="IP источника" value={filters.source} onChange={(value) => setFilters({ ...filters, source: value })} />
        <Input placeholder="IP назначения" value={filters.destination} onChange={(value) => setFilters({ ...filters, destination: value })} />
        <Input placeholder="код функции" value={filters.fc} onChange={(value) => setFilters({ ...filters, fc: value })} />
        <Input placeholder="ID устройства" value={filters.unit} onChange={(value) => setFilters({ ...filters, unit: value })} />
        <Select value={filters.action} onChange={(value) => setFilters({ ...filters, action: value })}>
          <option value="">решение</option>
          <option value="ALLOW">разрешено</option>
          <option value="BLOCK">заблокировано</option>
        </Select>
        <Input placeholder="адрес от" value={filters.addressFrom} onChange={(value) => setFilters({ ...filters, addressFrom: value })} />
        <Input placeholder="адрес до" value={filters.addressTo} onChange={(value) => setFilters({ ...filters, addressTo: value })} />
      </div>
      <DataTable
        columns={["Время", "Источник", "Назначение", "Устройство", "Код функции", "Адрес", "Количество", "Решение", "Правило", "Причина", "Задержка"]}
        empty="События трафика пока не зафиксированы"
      >
        {rows.map((row) => (
          <tr key={row.id}>
            <td>{formatTime(row.timestamp)}</td>
            <td>{row.source_ip || "-"}</td>
            <td>{row.destination_ip || "-"}</td>
            <td>{row.unit_id}</td>
            <td>FC{String(row.function_code).padStart(2, "0")}</td>
            <td>{row.start_address}</td>
            <td>{row.quantity}</td>
            <td><DecisionBadge value={row.result} /></td>
            <td>{row.meta?.matched_rule_id || "-"}</td>
            <td>{reasonLabel(row.reason)}</td>
            <td>{formatNumber(row.latency_ms, 2)} мс</td>
          </tr>
        ))}
      </DataTable>
    </Panel>
  );
}

function PoliciesPage({
  policies,
  activePolicy,
  candidatePolicy,
  applyResult,
  onApply,
  busy,
}: {
  policies: PolicyMetadata[];
  activePolicy: PolicyDetail | null;
  candidatePolicy: PolicyDetail | null;
  applyResult: Record<string, unknown> | null;
  onApply: (id?: string) => void;
  busy: string;
}) {
  const [selected, setSelected] = React.useState<"active" | "candidate">("active");
  React.useEffect(() => {
    if (candidatePolicy) {
      setSelected("candidate");
      return;
    }
    if (activePolicy) {
      setSelected("active");
    }
  }, [activePolicy, candidatePolicy]);
  const detail = selected === "active" ? activePolicy : candidatePolicy;
  const canApprove = selected === "candidate" && Boolean(candidatePolicy);
  return (
    <div className="grid gap-5 xl:grid-cols-[420px_1fr]">
      <Panel title="Список политик" icon={ShieldCheck}>
        <div className="space-y-3">
          {policies.length ? policies.map((policyItem) => (
            <button
              key={policyItem.id}
              className={`w-full rounded-md border p-3 text-left ${selected === policyItem.id ? "border-info bg-info/10" : "border-border bg-card-strong"}`}
              onClick={() => setSelected(policyItem.id as "active" | "candidate")}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="font-semibold">{policyItem.name}</div>
                {policyItem.active ? <StatusBadge tone="success">active</StatusBadge> : <StatusBadge tone="warning">ожидает approve</StatusBadge>}
              </div>
              <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-muted">
                <span>правил: {policyItem.rule_count}</span>
                <span>действие по умолчанию: {policyActionLabel(policyItem.default_action)}</span>
                <span>версия: {policyItem.version || "-"}</span>
                <span>{policyItem.validation_status}</span>
              </div>
            </button>
          )) : <EmptyState text="Активная политика отсутствует. Сформируйте кандидата по историческому трафику." />}
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button variant="primary" onClick={() => onApply(selected)} disabled={busy === "apply" || !canApprove}>
            <Save className="h-4 w-4" /> Утвердить кандидата
          </Button>
        </div>
        {applyResult ? (
          <div className="mt-4 rounded-md border border-success/40 bg-success/10 p-3 text-sm">
            <div className="font-semibold text-success">Кандидат утвержден как active policy</div>
            <div className="mt-2 grid gap-1 text-muted">
              <span>PID до применения: {String(applyResult.pid_before)}</span>
              <span>PID после применения: {String(applyResult.pid_after)}</span>
              <span>Потери соединений: {String(applyResult.connection_losses)}</span>
              <span>Candidate policy удалена после approve</span>
            </div>
          </div>
        ) : null}
      </Panel>

      <Panel title="Просмотр YAML" icon={FileCheck2}>
        <div className="mb-4 grid gap-3 md:grid-cols-4">
          <Kpi title="Количество правил" value={String(detail?.metadata.rule_count || 0)} />
          <Kpi title="Действие по умолчанию" value={policyActionLabel(detail?.metadata.default_action)} />
          <Kpi title="Дата создания" value={formatDate(detail?.metadata.created_at)} />
          <Kpi title="Статус валидации" value={detail?.metadata.validation_status || "-"} tone={detail?.metadata.validation_status === "валидна" ? "success" : "danger"} />
        </div>
        <pre className="code-block">{detail?.raw || "Файл политики не загружен"}</pre>
      </Panel>
    </div>
  );
}

function GenerationPage({
  writeThreshold,
  onWriteThresholdChange,
  onGenerate,
  summary,
  candidatePolicy,
  busy,
}: {
  writeThreshold: number;
  onWriteThresholdChange: (value: number) => void;
  onGenerate: () => void;
  summary: GenerationSummary | null;
  candidatePolicy: PolicyDetail | null;
  busy: string;
}) {
  const steps = [
    "чтение событий из истории",
    "выделение признаков Modbus TCP",
    "группировка по IP источника, IP назначения, устройству и коду функции",
    "разделение операций чтения и записи",
    "объединение диапазонов чтения",
    "отбор операций записи по порогу повторяемости",
    "формирование списка разрешенных операций",
    "сохранение candidate policy",
  ];
  return (
    <div className="grid gap-5 xl:grid-cols-[420px_1fr]">
      <Panel title="Параметры формирования" icon={SlidersHorizontal}>
        <label className="block text-sm text-muted">Порог повторяемости записей</label>
        <input
          className="mt-2 w-full rounded-md border border-border bg-[#08121d] px-3 py-2"
          type="number"
          min={1}
          value={writeThreshold}
          onChange={(event) => onWriteThresholdChange(Math.max(1, Math.floor(Number(event.target.value) || 1)))}
        />
        <p className="mt-2 text-xs text-muted">
          Значение 1 включает каждую уникальную операцию записи из истории. Значения выше 1 исключают редкие записи ниже порога повторяемости.
        </p>
        <Button className="mt-4 w-full justify-center" variant="primary" onClick={onGenerate} disabled={busy === "generate"}>
          <FileCog className="h-4 w-4" /> Сформировать политику
        </Button>
        <div className="mt-5 space-y-2">
          {steps.map((step, index) => (
            <div key={step} className="flex items-center gap-2 rounded-md border border-border bg-card-strong px-3 py-2 text-sm">
              <CheckCircle2 className="h-4 w-4 text-success" />
              <span>{index + 1}. {step}</span>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Результат формирования" icon={FileCheck2}>
        {summary ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <Kpi title="Событий обработано" value={formatNumber(summary.events_processed)} />
            <Kpi title="Групп сформировано" value={formatNumber(summary.groups_created)} />
            <Kpi title="Правил чтения" value={formatNumber(summary.read_rules)} />
            <Kpi title="Правил записи" value={formatNumber(summary.write_rules)} />
            <Kpi title="Диапазонов объединено" value={formatNumber(summary.ranges_merged)} />
            <Kpi title="Записей исключено" value={formatNumber(summary.write_operations_excluded)} />
            <Kpi title="Итоговое число правил" value={formatNumber(summary.rules_total)} tone="success" />
            <Kpi title="Порог записей" value={formatNumber(summary.write_threshold)} />
          </div>
        ) : (
          <EmptyState text="Сформируйте предварительную политику по накопленным событиям." />
        )}
        <pre className="code-block mt-4">{candidatePolicy?.raw || "Кандидат политики пока не сохранен"}</pre>
      </Panel>
    </div>
  );
}

function VerificationPage({
  report,
  selectedPolicy,
  hasActivePolicy,
  onVerify,
  busy,
}: {
  report: VerificationReport | null;
  selectedPolicy: PolicyID;
  hasActivePolicy: boolean;
  onVerify: (id?: PolicyID) => void;
  busy: string;
}) {
  return (
    <div className="space-y-5">
      <Panel title="Проверка политики на исторических событиях" icon={Search}>
        <div className="flex flex-wrap gap-2">
          <Button variant={selectedPolicy === "candidate" ? "primary" : "secondary"} onClick={() => onVerify("candidate")} disabled={busy === "verify"}>
            <FileCheck2 className="h-4 w-4" /> Проверить кандидата
          </Button>
          <Button variant={selectedPolicy === "active" ? "primary" : "secondary"} onClick={() => onVerify("active")} disabled={busy === "verify" || !hasActivePolicy}>
            <ShieldCheck className="h-4 w-4" /> Проверить активную
          </Button>
        </div>
      </Panel>
      {report ? (
        <Panel title="Отчет верификации" icon={FileCheck2}>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <Kpi title="Запросов штатного профиля" value={formatNumber(report.total_historical_requests)} />
            <Kpi title="Разрешено политикой" value={formatNumber(report.allowed_by_policy)} tone="success" />
            <Kpi title="Непокрыто политикой" value={formatNumber(report.uncovered_historical_requests ?? report.blocked_by_policy)} tone={report.blocked_by_policy ? "warning" : "success"} />
            <Kpi title="Ложные блокировки штатного обмена" value={formatNumber(report.false_positive)} tone={report.false_positive ? "danger" : "success"} />
            <Kpi title="Покрытие штатного трафика" value={`${formatNumber(report.normal_traffic_coverage, 2)} %`} />
            <Kpi title="Всего событий в истории" value={formatNumber(report.total_observed_requests ?? report.total_historical_requests)} />
            <Kpi title="Исключено запрещенных событий" value={formatNumber(report.excluded_forbidden_requests)} tone={report.excluded_forbidden_requests ? "warning" : "success"} />
          </div>
          <div className="mt-4 rounded-md border border-border bg-card-strong p-3 text-sm">
            {report.false_positive === 0 ? (
              <div className="flex items-center gap-2 text-success"><CheckCircle2 className="h-4 w-4" /> ложные блокировки: 0</div>
            ) : (
              <div className="flex items-center gap-2 text-danger"><AlertTriangle className="h-4 w-4" /> Требуется анализ непокрытых операций</div>
            )}
            {report.blocked_by_policy > 0 ? (
              <div className="mt-2 text-muted">
                Непокрытые исторические запросы не считаются ложными блокировками автоматически: они требуют классификации как штатные или запрещенные операции.
              </div>
            ) : null}
            {(report.excluded_forbidden_requests || 0) > 0 ? (
              <div className="mt-2 text-muted">
                События от источников вне промышленного профиля исключены из расчета покрытия штатной политики и учитываются как запрещенный трафик.
              </div>
            ) : null}
          </div>
        </Panel>
      ) : null}
    </div>
  );
}

function LogsPage({ events, traffic }: { events: SystemEvent[]; traffic: TrafficEvent[] }) {
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Системные события" icon={TerminalSquare}>
        <EventList events={events.slice().reverse()} />
      </Panel>
      <Panel title="Решения фильтрации" icon={Shield}>
        <DataTable columns={["Время", "Режим", "Код функции", "Адрес", "Решение", "Причина"]} empty="Журнал решений пуст">
          {traffic.slice().reverse().map((row) => (
            <tr key={row.id}>
              <td>{formatTime(row.timestamp)}</td>
              <td>{modeLabel(row.mode)}</td>
              <td>FC{String(row.function_code).padStart(2, "0")}</td>
              <td>{row.start_address}</td>
              <td><DecisionBadge value={row.result} /></td>
              <td>{reasonLabel(row.reason)}</td>
            </tr>
          ))}
        </DataTable>
      </Panel>
    </div>
  );
}

function SettingsPage({ apiBase, status }: { apiBase: string; status: StatusPayload | null }) {
  return (
    <Panel title="Параметры подключения" icon={Settings}>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Kpi title="Адрес API" value={apiBase} />
        <Kpi title="PID" value={String(status?.pid || "-")} />
        <Kpi title="Режим" value={modeLabel(status?.mode)} />
        <Kpi title="Активные соединения" value={formatNumber(status?.active_connections)} />
      </div>
    </Panel>
  );
}

function Kpi({ title, value, tone = "default" }: { title: string; value: string; tone?: "default" | "success" | "danger" | "warning" }) {
  const color = tone === "success" ? "text-success" : tone === "danger" ? "text-danger" : tone === "warning" ? "text-warning" : "text-foreground";
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="truncate text-xs uppercase tracking-wide text-muted">{title}</div>
      <div className={`mt-2 truncate text-xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}

function Panel({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="mb-4 flex items-center gap-2">
        <Icon className="h-5 w-5 text-info" />
        <h2 className="text-base font-semibold">{title}</h2>
      </div>
      {children}
    </section>
  );
}

function ConfirmDialog({
  request,
  onResolve,
}: {
  request: ConfirmRequest | null;
  onResolve: (confirmed: boolean) => void;
}) {
  if (!request) return null;
  const toneClass =
    request.tone === "danger"
      ? "border-danger/50 bg-danger/10 text-red-100"
      : request.tone === "warning"
        ? "border-warning/50 bg-warning/10 text-yellow-100"
        : "border-info/50 bg-info/10 text-sky-100";
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-lg rounded-lg border border-border bg-[#0b1420] p-5 shadow-2xl">
        <div className={`mb-4 rounded-md border px-3 py-2 ${toneClass}`}>
          <div className="font-semibold">{request.title}</div>
          <div className="mt-1 text-sm text-muted">{request.message}</div>
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={() => onResolve(false)}>
            Отмена
          </Button>
          <Button variant={request.tone === "warning" ? "warning" : "primary"} onClick={() => onResolve(true)}>
            {request.confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

function Button({
  children,
  variant = "secondary",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "warning" }) {
  const variantClass = variant === "primary"
    ? "border-success/70 bg-success/15 text-green-100 hover:bg-success/25"
    : variant === "warning"
      ? "border-warning/70 bg-warning/15 text-yellow-100 hover:bg-warning/25"
      : "border-border bg-card-strong text-foreground hover:border-info";
  return (
    <button
      className={`inline-flex h-9 items-center gap-2 rounded-md border px-3 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50 ${variantClass} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

function StatusBadge({ tone, children }: { tone: "success" | "danger" | "warning" | "default"; children: React.ReactNode }) {
  const cls = tone === "success" ? "badge-success" : tone === "danger" ? "badge-danger" : tone === "warning" ? "badge-warning" : "badge-default";
  return <span className={`badge ${cls}`}>{children}</span>;
}

function DecisionBadge({ value }: { value: string }) {
  const allow = value === "ALLOW";
  return <StatusBadge tone={allow ? "success" : "danger"}>{allow ? "разрешено" : "заблокировано"}</StatusBadge>;
}

function Input({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) {
  return (
    <input
      className="h-9 rounded-md border border-border bg-[#08121d] px-3 text-sm outline-none focus:border-info"
      value={value}
      placeholder={placeholder}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

function Select({ value, onChange, children }: { value: string; onChange: (value: string) => void; children: React.ReactNode }) {
  return (
    <select
      className="h-9 rounded-md border border-border bg-[#08121d] px-3 text-sm outline-none focus:border-info"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    >
      {children}
    </select>
  );
}

function DataTable({ columns, children, empty }: { columns: string[]; children: React.ReactNode; empty: string }) {
  const rows = React.Children.count(children);
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full min-w-[920px] border-collapse text-sm">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>{rows > 0 ? children : <tr><td colSpan={columns.length}><EmptyState text={empty} /></td></tr>}</tbody>
      </table>
    </div>
  );
}

function EventList({ events }: { events: SystemEvent[] }) {
  if (events.length === 0) return <EmptyState text="События пока не зафиксированы" />;
  return (
    <div className="space-y-2">
      {events.map((event) => (
        <div key={event.id} className="rounded-md border border-border bg-card-strong p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="font-semibold">{eventTypeLabel(event.type)}</div>
            <StatusBadge tone={event.severity === "ERROR" ? "danger" : event.severity === "WARN" ? "warning" : "default"}>{severityLabel(event.severity)}</StatusBadge>
          </div>
          <div className="mt-1 text-sm text-muted">{formatTime(event.timestamp)} · {eventMessageLabel(event.message)}</div>
        </div>
      ))}
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="flex min-h-24 items-center justify-center rounded-md border border-dashed border-border bg-[#08121d] px-4 py-6 text-center text-sm text-muted">
      {text}
    </div>
  );
}

function ChartFrame({ children }: { children: React.ReactElement }) {
  return <div className="h-72 w-full"><ResponsiveContainer>{children}</ResponsiveContainer></div>;
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
