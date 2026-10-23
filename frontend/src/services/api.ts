import type { Finding, ScanMetadata, AttackGraphData, ProposedFix, AgentTraceEvent } from '../types/finding';

export interface SystemStatus {
  backend: 'ok' | 'unreachable';
  analysisService: 'ok' | 'unreachable' | 'degraded';
  timestamp: string;
}

export interface ScanResponse {
  metadata: ScanMetadata;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    active?: number;
    dismissed?: number;
    fixesProposed?: number;
    fixesVerified?: number;
  };
  findings: Finding[];
  graph?: AttackGraphData;
  fixes?: ProposedFix[];
  agentTrace?: AgentTraceEvent[];
}

export interface ExplainFindingResponse {
  success: boolean;
  findingId: string;
  explanation: string;
  isFallback: boolean;
  fallbackReason?: string | null;
  model?: string | null;
  cached?: boolean;
}

export interface UserProfile {
  id: number | string;
  username: string;
  name?: string;
  avatarUrl?: string;
}

export interface AuthMeResponse {
  authenticated: boolean;
  user?: UserProfile;
  error?: string;
}

export interface GitHubRepo {
  name: string;
  full_name: string;
  private: boolean;
  description: string;
  default_branch: string;
  html_url: string;
  updated_at: string;
}

export const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';

/**
 * Calls backend /api/status to verify connectivity across frontend -> backend -> analysis-service
 */
export async function getSystemStatus(): Promise<SystemStatus> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3-second timeout

    const response = await fetch(`${BACKEND_URL}/api/status`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        backend: 'unreachable',
        analysisService: 'unreachable',
        timestamp: new Date().toISOString(),
      };
    }

    const data = await response.json();
    return {
      backend: data.backend || 'ok',
      analysisService: data.analysisService || 'unreachable',
      timestamp: data.timestamp || new Date().toISOString(),
    };
  } catch {
    return {
      backend: 'unreachable',
      analysisService: 'unreachable',
      timestamp: new Date().toISOString(),
    };
  }
}

/**
 * Uploads a .zip repository archive to backend /api/scan/upload for static security analysis
 */
export async function uploadAndScanArchive(file: File): Promise<ScanResponse> {
  const formData = new FormData();
  formData.append('file', file, file.name);

  let response: Response;
  try {
    response = await fetch(`${BACKEND_URL}/api/scan/upload`, {
      method: 'POST',
      credentials: 'include',
      body: formData,
    });
  } catch {
    throw new Error(
      `Unable to connect to backend server at ${BACKEND_URL}. Please ensure the backend is running.`
    );
  }

  if (!response.ok) {
    let errorMessage = `Scan failed (HTTP ${response.status})`;
    try {
      const errorJson = await response.json();
      if (errorJson && errorJson.error) {
        errorMessage = errorJson.error;
      }
    } catch {
      // Non-JSON error body fallback
    }
    throw new Error(errorMessage);
  }

  const data: ScanResponse = await response.json();
  return data;
}

/**
 * Requests scanning of a remote repository URL via backend /api/scan/repo
 */
export async function scanRepositoryUrl(repoUrl: string): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(`${BACKEND_URL}/api/scan/repo`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({ repoUrl }),
    });
  } catch {
    throw new Error(
      `Unable to connect to backend server at ${BACKEND_URL}. Please ensure the backend is running.`
    );
  }

  if (response.status === 501) {
    let msg = "GitHub repository scanning isn't available yet — try uploading a .zip instead.";
    try {
      const errorJson = await response.json();
      if (errorJson && errorJson.error) {
        msg = errorJson.error;
      }
    } catch {}
    throw new Error(msg);
  }

  if (!response.ok) {
    let errorMessage = `Scan failed (HTTP ${response.status})`;
    try {
      const errorJson = await response.json();
      if (errorJson && errorJson.error) {
        errorMessage = errorJson.error;
      }
    } catch {}
    throw new Error(errorMessage);
  }

  const data: ScanResponse = await response.json();
  return data;
}

/**
 * Requests an on-demand AI explanation for a specific security finding.
 * The backend handles Gemini generation, caching, and automatic fallback to static guidance.
 */
export async function explainFinding(finding: Finding): Promise<ExplainFindingResponse> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/findings/${encodeURIComponent(finding.id)}/explain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({ finding }),
    });

    if (!response.ok) {
      return {
        success: true,
        findingId: finding.id,
        explanation: finding.remediation || 'Apply proper input validation and security controls.',
        isFallback: true,
        fallbackReason: `HTTP ${response.status}`,
      };
    }

    const data: ExplainFindingResponse = await response.json();
    return data;
  } catch (err: any) {
    return {
      success: true,
      findingId: finding.id,
      explanation: finding.remediation || 'Apply proper input validation and security controls.',
      isFallback: true,
      fallbackReason: err?.message || 'Network error',
    };
  }
}

/**
 * Checks session authentication status by calling GET /api/auth/me
 */
export async function getAuthMe(): Promise<AuthMeResponse> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/auth/me`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      credentials: 'include',
    });

    if (!response.ok) {
      return { authenticated: false };
    }

    const data = await response.json();
    return {
      authenticated: Boolean(data.authenticated),
      user: data.user,
    };
  } catch {
    return { authenticated: false };
  }
}

/**
 * Terminates session by calling POST /api/auth/logout
 */
export async function logoutAuth(): Promise<boolean> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/auth/logout`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
      },
      credentials: 'include',
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Fetches user repositories from GitHub via backend /api/github/repos
 */
export async function getGithubRepos(options: { page?: number; per_page?: number } = {}): Promise<GitHubRepo[]> {
  const { page = 1, per_page = 100 } = options;
  const url = new URL(`${BACKEND_URL}/api/github/repos`);
  url.searchParams.set('page', String(page));
  url.searchParams.set('per_page', String(per_page));

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
    credentials: 'include',
  });

  if (!response.ok) {
    let errorMessage = `Failed to fetch repositories (${response.status})`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.error) {
        errorMessage = errJson.error;
      }
    } catch {}
    throw new Error(errorMessage);
  }

  const data = await response.json();
  return Array.isArray(data) ? data : [];
}

/**
 * Approve a proposed patch to be applied to the ephemeral scan copy.
 */
export async function approveFix(fixId: string): Promise<{ success: boolean; fix?: ProposedFix; message?: string }> {
  const response = await fetch(`${BACKEND_URL}/api/fixes/${encodeURIComponent(fixId)}/approve`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    credentials: 'include',
  });

  if (!response.ok) {
    let errMsg = `Failed to approve fix (${response.status})`;
    try {
      const err = await response.json();
      if (err?.error) errMsg = err.error;
    } catch {}
    throw new Error(errMsg);
  }

  return response.json();
}

/**
 * Reject a proposed patch.
 */
export async function rejectFix(fixId: string, reason?: string): Promise<{ success: boolean; fix?: ProposedFix; message?: string }> {
  const response = await fetch(`${BACKEND_URL}/api/fixes/${encodeURIComponent(fixId)}/reject`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify({ reason }),
  });

  if (!response.ok) {
    let errMsg = `Failed to reject fix (${response.status})`;
    try {
      const err = await response.json();
      if (err?.error) errMsg = err.error;
    } catch {}
    throw new Error(errMsg);
  }

  return response.json();
}

/**
 * Retrieve all proposed fixes for a given scan or across active scans.
 * Throws when backend is stopped or uncontactable so UI can display error state.
 */
export async function getScanFixes(scanId?: string): Promise<ProposedFix[]> {
  const url = scanId ? `${BACKEND_URL}/api/scan/${encodeURIComponent(scanId)}/fixes` : `${BACKEND_URL}/api/fixes`;
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
    credentials: 'include',
  });

  if (!response.ok) {
    let errMsg = `Backend responded with status ${response.status}`;
    try {
      const err = await response.json();
      if (err?.error) errMsg = err.error;
    } catch {}
    throw new Error(errMsg);
  }

  const data = await response.json();
  return Array.isArray(data.fixes) ? data.fixes : [];
}

/**
 * Create an SSE EventSource connection to stream agent trace events for a scan.
 */
export function getAgentTraceEventSource(scanId: string): EventSource {
  return new EventSource(`${BACKEND_URL}/api/scan/${encodeURIComponent(scanId)}/agent-trace`);
}

