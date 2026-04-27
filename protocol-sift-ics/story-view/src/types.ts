export type MitrePhase =
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection"
  | "command_and_control"
  | "exfiltration"
  | "impact";

export type ConfidenceTier =
  | "confirmed"
  | "inferred"
  | "hypothesized"
  | "contradicted";

export type Branch = "forensics" | "memory" | "network" | "malware" | "triage";

export interface AttackPhaseEntry {
  phase: MitrePhase;
  mitre_technique_id: string;
  mitre_technique_name: string;
  narrative: string;
  supporting_findings: string[];
  timestamp_first_observed: string;
  timestamp_last_observed: string;
  confidence: ConfidenceTier;
}

export interface IocBase {
  first_seen?: string;
  supporting_findings: string[];
}
export interface FileHashIoc extends IocBase {
  value: string;
  algorithm: "sha256" | "md5" | "sha1";
}
export interface IpIoc extends IocBase {
  value: string;
  direction: "inbound" | "outbound";
}
export interface DomainIoc extends IocBase {
  value: string;
}
export interface RegistryIoc extends IocBase {
  key: string;
  value_name: string;
}
export interface FilePathIoc extends IocBase {
  path: string;
  host: string;
}

export interface Iocs {
  file_hashes: FileHashIoc[];
  ip_addresses: IpIoc[];
  domains: DomainIoc[];
  registry_keys: RegistryIoc[];
  file_paths: FilePathIoc[];
}

export interface OperationalPeriodSummary {
  period: number;
  objectives: string[];
  active_branches: Branch[];
  key_findings_added: string[];
  ic_reasoning: string;
}

export interface FinalReport {
  case_id: string;
  incident_summary: string;
  attack_narrative: AttackPhaseEntry[];
  iocs: Iocs;
  operational_periods_summary: OperationalPeriodSummary[];
  generated_at?: string;
  primary_hosts?: string[];
}

export interface Finding {
  id: string;
  branch: Branch;
  category: string;
  title: string;
  description: string;
  evidence_source: string;
  tool_execution_id: string;
  confidence_tier: ConfidenceTier;
  confidence_score: number;
  timestamp_observed: string;
  structured_data: Record<string, unknown>;
  supports_phase: MitrePhase;
  mitre_technique_ids: string[];
  operational_period_id: number;
  host?: string;
}

export interface FindingsFile {
  findings: Finding[];
}

export interface EvidenceItem {
  id: string;
  type: string;
  host: string;
  sha256?: string;
  size_bytes?: number;
}

export interface CrossSource {
  source: string;
  finding: string;
}

export interface EstablishedFact {
  fact: string;
  established_in_period: number;
  supporting_findings: string[];
  confidence_tier: ConfidenceTier;
  cross_source_corroboration: CrossSource[];
}

export interface ContradictionResolved {
  description: string;
  resolution: string;
  in_period: number;
}

export interface CommonOperatingPicture {
  incident_id: string;
  as_of_period: number;
  evidence_inventory: EvidenceItem[];
  established_facts: EstablishedFact[];
  open_questions: string[];
  contradictions_resolved: ContradictionResolved[];
}

export type AuditEventType =
  | "tool_invocation"
  | "finding_produced"
  | "inter_skill_message"
  | "period_boundary"
  | "safety_halt"
  | "safety_clear"
  | "ic_reasoning"
  | "objective_set";

export interface AuditEntry {
  audit_id: string;
  timestamp: string;
  subagent: string;
  event_type: AuditEventType;
  payload: Record<string, unknown> & {
    finding_id?: string;
    tool_execution_id?: string;
    parent_audit_id?: string;
    mcp_function?: string;
    parameters?: Record<string, unknown>;
    message?: string;
    period?: number;
    objective?: string;
    reasoning?: string;
  };
  prev_hash: string;
  this_hash: string;
}

export interface CaseData {
  finalReport: FinalReport;
  findings: Finding[];
  findingsById: Map<string, Finding>;
  cop: CommonOperatingPicture;
  auditLog: AuditEntry[];
  auditById: Map<string, AuditEntry>;
}
