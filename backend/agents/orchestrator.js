import fs from 'fs';
import path from 'path';
import { runPlannerAgent } from './plannerAgent.js';
import { runVerifierAgent } from './verifierAgent.js';
import { runFixAgent, fixesStore } from './fixAgent.js';
import { buildAttackGraph } from '../src/services/graphService.js';
import { registerScanFindings } from '../src/services/llmExplanationService.js';

/**
 * Stores active scans and their ephemeral directories for human-in-the-loop patch application
 */
export const activeScansStore = new Map();

/**
 * Trace event buffer per scanId
 */
export const traceHistoryStore = new Map();

/**
 * Connected SSE subscribers per scanId
 */
export const sseSubscribers = new Map();

/**
 * Emits an agent trace event to in-memory history and active SSE streams
 */
export function emitAgentTrace(scanId, event) {
  if (!traceHistoryStore.has(scanId)) {
    traceHistoryStore.set(scanId, []);
  }

  const payload = {
    ...event,
    scanId,
    timestamp: event.timestamp || new Date().toISOString(),
  };

  traceHistoryStore.get(scanId).push(payload);

  const clients = sseSubscribers.get(scanId);
  if (clients && clients.size > 0) {
    const sseData = `data: ${JSON.stringify(payload)}\n\n`;
    for (const client of clients) {
      try {
        client.write(sseData);
      } catch (err) {
        clients.delete(client);
      }
    }
  }
}

/**
 * Subscribes an HTTP response stream to real-time agent SSE events for a scanId
 */
export function subscribeAgentTrace(scanId, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });

  if (!sseSubscribers.has(scanId)) {
    sseSubscribers.set(scanId, new Set());
  }
  const clients = sseSubscribers.get(scanId);
  clients.add(res);

  // Send initial comment to open stream
  res.write(': connected\n\n');

  // Replay past buffered events for this scan
  const history = traceHistoryStore.get(scanId) || [];
  for (const event of history) {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  }

  // Handle client disconnect
  res.on('close', () => {
    clients.delete(res);
    if (clients.size === 0) {
      sseSubscribers.delete(scanId);
    }
  });
}

/**
 * Category mapper matching frontend FindingCategory
 */
function mapCategory(ruleId = '', category = '') {
  const upperRule = String(ruleId || '').toUpperCase();
  const upperCat = String(category || '').toUpperCase();

  if (upperRule.includes('SECRET') || upperCat.includes('SECRET')) return 'secret';
  if (
    upperRule.includes('SQL') ||
    upperRule.includes('INJECTION') ||
    upperCat.includes('INJECTION') ||
    upperRule.includes('XSS') ||
    upperCat.includes('CROSS-SITE') ||
    upperCat.includes('XSS')
  ) {
    return 'injection';
  }
  if (upperRule.includes('DEPENDENCY') || upperCat.includes('DEPENDENCY') || upperCat.includes('VULNERABLE')) {
    return 'dependency';
  }
  if (
    upperRule.includes('ANTIPATTERN') ||
    upperCat.includes('ANTIPATTERN') ||
    upperCat.includes('RATE_LIMIT')
  ) {
    return 'ai-antipattern';
  }
  return 'validation';
}

/**
 * Language detector based on file extension
 */
function detectLanguage(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  if (ext === '.ts' || ext === '.tsx') return 'typescript';
  if (ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') return 'javascript';
  if (ext === '.py' || ext === '.pyw') return 'python';
  if (ext === '.json') return 'json';
  if (base.endsWith('.toml')) return 'toml';
  if (base.includes('requirements') && ext === '.txt') return 'plaintext';
  return 'plaintext';
}

/**
 * Builds code snippet context around finding
 */
function buildCodeSnippet(fileContent, finding, relPath) {
  const lines = (fileContent || '').split(/\r?\n/);
  const targetStart = Math.max(1, finding.line_number || finding.startLine || 1);
  const targetEnd = Math.max(targetStart, finding.end_line_number || finding.endLine || targetStart);

  const startLine = Math.max(1, targetStart - 3);
  const endLine = Math.min(lines.length, targetEnd + 3);

  const snippetLines = lines.slice(startLine - 1, endLine);
  const highlightLines = [];
  for (let l = targetStart; l <= targetEnd; l++) {
    if (l >= startLine && l <= endLine) highlightLines.push(l);
  }

  return {
    language: detectLanguage(relPath),
    startLine,
    lines: snippetLines,
    highlightLines: highlightLines.length > 0 ? highlightLines : [targetStart],
    highlightMessage: finding.title || finding.description,
  };
}

/**
 * Orchestrator Agent: coordinates Planner -> Detectors -> Verifier -> Fix Agent
 *
 * @param {string} targetDir - Directory containing codebase files
 * @param {Array<object>} targetFiles - Discovered source files
 * @param {object} context - Scan metadata { scanId, repoName, branch, commitHash, startTime }
 * @returns {Promise<object>} Complete scan result with verified findings, proposed fixes, and attack graph
 */
export async function runAgenticOrchestrator(targetDir, targetFiles, context) {
  const { scanId, repoName, branch = 'main', commitHash, startTime = Date.now() } = context;

  const onTrace = (event) => emitAgentTrace(scanId, event);

  onTrace({
    agent: 'Orchestrator',
    step: 'pipeline_init',
    tool: 'agent_supervisor',
    input_summary: `Initializing Agentic Scan pipeline for ${repoName} (${targetFiles.length} files)`,
    output_summary: 'Registered execution pipeline: Planner -> AST Detectors -> Verifier -> Fix Agent',
    timestamp: new Date().toISOString(),
  });

  // 1. Planner Agent
  const plannerResult = await runPlannerAgent(targetFiles, targetDir, { onTrace });
  const rawFindings = plannerResult.findings || [];

  // Deduplicate and enrich raw findings with snippets
  let findingIndex = 1;
  const processedFindings = [];

  for (const raw of rawFindings) {
    const relPath = raw.file_path || raw.sourceFile || 'file';
    const fullPath = path.join(targetDir, relPath);
    let content = '';
    try {
      content = fs.readFileSync(fullPath, 'utf8');
    } catch {}

    const severity = (raw.severity || 'low').toLowerCase();
    const category = mapCategory(raw.rule_id, raw.category);
    const codeSnippet = buildCodeSnippet(content, raw, relPath);
    const catPrefix = category === 'ai-antipattern' ? 'ant' : category.slice(0, 3);

    processedFindings.push({
      id: `cg-${catPrefix}-${String(findingIndex++).padStart(3, '0')}`,
      title: raw.title || 'Security Finding',
      severity: severity === 'info' ? 'low' : severity,
      category,
      filePath: relPath,
      startLine: raw.line_number || 1,
      endLine: raw.end_line_number || raw.line_number || 1,
      description: raw.description || '',
      remediation: raw.remediation || '',
      cwe: raw.cwe_id || undefined,
      rule_id: raw.rule_id || undefined,
      codeSnippet,
      sourceExpression: raw.source_expression || undefined,
      sourceLine: raw.source_line || undefined,
      sinkExpression: raw.sink_expression || undefined,
      sinkLine: raw.sink_line || undefined,
    });
  }

  // 2. Verifier Agent: Filter false positives (conf >= 0.7 -> dismissed)
  const verifiedFindings = await runVerifierAgent(processedFindings, targetDir, { onTrace });

  // 3. Fix Agent: Iterative ReAct loop with analysis-service rescan (stores patches as "pending")
  const proposedFixes = await runFixAgent(verifiedFindings, targetDir, { scanId, onTrace });

  // 4. Attack Graph & Summary
  const activeFindings = verifiedFindings.filter(f => f.status !== 'dismissed');
  const graph = buildAttackGraph(activeFindings);

  const durationMs = Date.now() - startTime;
  const summary = {
    total: verifiedFindings.length,
    active: activeFindings.length,
    dismissed: verifiedFindings.filter(f => f.status === 'dismissed').length,
    fixesProposed: proposedFixes.length,
    fixesVerified: proposedFixes.filter(f => f.success).length,
    critical: activeFindings.filter(f => f.severity === 'critical').length,
    high: activeFindings.filter(f => f.severity === 'high').length,
    medium: activeFindings.filter(f => f.severity === 'medium').length,
    low: activeFindings.filter(f => f.severity === 'low').length,
  };

  // LLM Explanation registration for backward compatibility
  registerScanFindings(verifiedFindings);

  const fullResult = {
    metadata: {
      scanId,
      repoName,
      branch,
      commitHash: commitHash || scanId.slice(-7),
      scanTimestamp: new Date().toISOString(),
      durationMs,
      filesScanned: targetFiles.length,
      linesAnalyzed: targetFiles.reduce((acc, f) => {
        try {
          return acc + fs.readFileSync(f.fullPath, 'utf8').split('\n').length;
        } catch {
          return acc;
        }
      }, 0),
    },
    summary,
    findings: verifiedFindings,
    fixes: proposedFixes,
    graph,
    agentTrace: traceHistoryStore.get(scanId) || [],
  };

  // Retain active scan reference for human-in-the-loop patch approval
  activeScansStore.set(scanId, {
    targetDir,
    scanResult: fullResult,
    expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
  });

  onTrace({
    agent: 'Orchestrator',
    step: 'pipeline_completed',
    tool: 'agent_supervisor',
    input_summary: `Scan ${scanId} finished in ${durationMs}ms`,
    output_summary: `Pipeline complete: ${activeFindings.length} active findings, ${summary.dismissed} dismissed, ${proposedFixes.length} pending fixes ready for review`,
    timestamp: new Date().toISOString(),
  });

  return fullResult;
}

/**
 * Human-in-the-loop: Approves and applies a proposed patch to the ephemeral scan directory
 */
export function approveFix(fixId) {
  const fix = fixesStore.get(fixId);
  if (!fix) {
    throw new Error(`Proposed fix '${fixId}' not found.`);
  }

  if (fix.status === 'approved') {
    return { success: true, message: 'Fix already approved and applied', fix };
  }

  const scanInfo = activeScansStore.get(fix.scanId);
  if (!scanInfo || !scanInfo.targetDir) {
    throw new Error(`Active scan directory for scanId '${fix.scanId}' is no longer available.`);
  }

  const targetFilePath = path.join(scanInfo.targetDir, fix.filePath);
  try {
    fs.mkdirSync(path.dirname(targetFilePath), { recursive: true });
    fs.writeFileSync(targetFilePath, fix.patchedCode, 'utf8');
  } catch (err) {
    throw new Error(`Failed to write patched file: ${err.message}`);
  }

  fix.status = 'approved';
  fix.appliedAt = new Date().toISOString();

  // Update associated finding if present
  if (scanInfo.scanResult?.findings) {
    const finding = scanInfo.scanResult.findings.find(f => f.id === fix.findingId);
    if (finding) {
      finding.status = 'fixed';
      finding.fixedAt = fix.appliedAt;
    }
  }

  emitAgentTrace(fix.scanId, {
    agent: 'Orchestrator',
    step: 'fix_approved',
    tool: 'human_in_the_loop',
    input_summary: `Approved fix ${fixId} for ${fix.filePath}`,
    output_summary: 'Applied patch to ephemeral scan codebase copy',
    timestamp: new Date().toISOString(),
  });

  return {
    success: true,
    message: `Fix ${fixId} successfully approved and applied to ${fix.filePath}`,
    fix,
  };
}

/**
 * Human-in-the-loop: Rejects a proposed patch
 */
export function rejectFix(fixId) {
  const fix = fixesStore.get(fixId);
  if (!fix) {
    throw new Error(`Proposed fix '${fixId}' not found.`);
  }

  fix.status = 'rejected';
  fix.rejectedAt = new Date().toISOString();

  emitAgentTrace(fix.scanId, {
    agent: 'Orchestrator',
    step: 'fix_rejected',
    tool: 'human_in_the_loop',
    input_summary: `Rejected fix ${fixId} for ${fix.filePath}`,
    output_summary: 'Patch marked as rejected. No changes made to codebase.',
    timestamp: new Date().toISOString(),
  });

  return {
    success: true,
    message: `Fix ${fixId} rejected.`,
    fix,
  };
}

/**
 * Retrieves all proposed fixes for a scan
 */
export function getScanFixes(scanId) {
  const fixes = [];
  for (const fix of fixesStore.values()) {
    if (fix.scanId === scanId) {
      fixes.push(fix);
    }
  }
  return fixes;
}
