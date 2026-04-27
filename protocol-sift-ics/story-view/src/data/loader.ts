import type {
  AuditEntry,
  CaseData,
  CommonOperatingPicture,
  Finding,
  FindingsFile,
  FinalReport,
} from "../types";

// Production build: try ./case/ first (real swarm output), fall back to ./case-stub/.
// Development: prefer /case-stub/ so the dev server has data without copying.
const CASE_BASES = import.meta.env.DEV
  ? ["/case-stub", "./case"]
  : ["./case", "./case-stub"];

async function fetchFirst(path: string): Promise<Response> {
  let lastErr: string | null = null;
  for (const base of CASE_BASES) {
    try {
      const res = await fetch(`${base}/${path}`);
      if (res.ok) return res;
      lastErr = `HTTP ${res.status} at ${base}/${path}`;
    } catch (e) {
      lastErr = `${(e as Error).message} at ${base}/${path}`;
    }
  }
  throw new Error(lastErr ?? `Failed to load ${path}`);
}

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetchFirst(path);
  return (await res.json()) as T;
}

async function fetchJsonl<T>(path: string): Promise<T[]> {
  const res = await fetchFirst(path);
  const text = await res.text();
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as T);
}

export async function loadCase(): Promise<CaseData> {
  const [finalReport, findingsFile, cop, auditLog] = await Promise.all([
    fetchJson<FinalReport>("final_report.json"),
    fetchJson<FindingsFile>("findings.json"),
    fetchJson<CommonOperatingPicture>("cop.json"),
    fetchJsonl<AuditEntry>("audit_log.jsonl"),
  ]);

  const findings = findingsFile.findings;
  const findingsById = new Map<string, Finding>(
    findings.map((f) => [f.id, f])
  );
  const auditById = new Map<string, AuditEntry>(
    auditLog.map((a) => [a.audit_id, a])
  );

  return { finalReport, findings, findingsById, cop, auditLog, auditById };
}
