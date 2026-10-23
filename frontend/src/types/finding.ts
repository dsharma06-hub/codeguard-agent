export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory = 
  | 'secret'
  | 'injection'
  | 'xss'
  | 'Cross-Site Scripting'
  | 'dependency'
  | 'validation'
  | 'complexity'
  | 'ai-antipattern';

export interface CodeSnippetData {
  language: string;
  startLine: number;
  lines: string[];
  highlightLines: number[]; // 1-based absolute line numbers within the file
  highlightMessage?: string;
}

export type FindingStatus = 'verified' | 'dismissed' | 'pending' | 'fixed';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  filePath: string;
  startLine: number;
  endLine: number;
  description: string;
  remediation: string;
  cwe?: string;
  codeSnippet: CodeSnippetData;
  // Agentic AI fields
  status?: FindingStatus;
  verifierVerdict?: 'true_positive' | 'false_positive';
  verifierConfidence?: number;
  verifierReasoning?: string;
  fixId?: string;
  fixStatus?: 'pending' | 'approved' | 'rejected';
}

export interface ReActIteration {
  iteration: number;
  reason: string;
  act: string;
  observe: string;
  timestamp: string;
}

export interface ProposedFix {
  id: string;
  findingId: string;
  scanId: string;
  filePath: string;
  cwe?: string;
  title: string;
  severity: Severity;
  status: 'pending' | 'approved' | 'rejected';
  diff: string;
  patchedContent?: string;
  retryCount: number;
  verifierReasoning?: string;
  verifierConfidence?: number;
  history: ReActIteration[];
  success: boolean;
  createdAt: string;
}

export interface AgentTraceEvent {
  agent: 'Planner' | 'Verifier' | 'FixAgent' | 'Orchestrator' | string;
  step: string;
  tool?: string;
  input_summary: string;
  output_summary: string;
  timestamp: string;
  scanId?: string;
}

export interface ScanMetadata {
  scanId?: string;
  repoName: string;
  branch: string;
  commitHash: string;
  scanTimestamp: string;
  durationMs: number;
  filesScanned: number;
  linesAnalyzed: number;
}

export type GraphNodeType = 'file' | 'vulnerability' | 'source';

export interface AttackGraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  severity?: Severity;
  category?: FindingCategory;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface AttackGraphData {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}
