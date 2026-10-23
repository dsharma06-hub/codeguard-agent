import fs from 'fs';
import path from 'path';
import { config } from '../src/config/env.js';

export const PLANNER_TOOLS = [
  {
    function_declarations: [
      {
        name: 'run_secrets_scan',
        description: 'Runs static secret detection on source files to identify hardcoded API keys, private keys, database passwords, and tokens.',
        parameters: {
          type: 'OBJECT',
          properties: {
            reason: {
              type: 'STRING',
              description: 'Explanation for why secret detection is recommended for this codebase.'
            }
          }
        }
      },
      {
        name: 'run_sqli_scan',
        description: 'Runs AST taint analysis for SQL Injection vulnerabilities on database query sinks and string interpolations.',
        parameters: {
          type: 'OBJECT',
          properties: {
            reason: {
              type: 'STRING',
              description: 'Explanation for why SQL injection analysis is recommended for this codebase.'
            }
          }
        }
      },
      {
        name: 'run_xss_scan',
        description: 'Runs AST analysis for Cross-Site Scripting (XSS) in frontend/DOM sinks and Server-Side Template Injection (SSTI) in backend templates.',
        parameters: {
          type: 'OBJECT',
          properties: {
            reason: {
              type: 'STRING',
              description: 'Explanation for why XSS / SSTI scanning is recommended for this codebase.'
            }
          }
        }
      },
      {
        name: 'run_dependency_scan',
        description: 'Scans package manifests (package.json, requirements.txt, pyproject.toml) against vulnerability databases for known CVEs.',
        parameters: {
          type: 'OBJECT',
          properties: {
            reason: {
              type: 'STRING',
              description: 'Explanation for why dependency scanning is recommended for this codebase.'
            }
          }
        }
      }
    ]
  }
];

/**
 * Executes a single analysis-service detector endpoint for target files
 */
async function executeDetector(detectorName, targetFiles, targetDir) {
  const endpointMap = {
    run_secrets_scan: '/analyze/secrets',
    run_sqli_scan: '/analyze/sql-injection',
    run_xss_scan: '/analyze/xss',
    run_dependency_scan: '/analyze/dependencies',
  };

  const endpoint = endpointMap[detectorName] || '/analyze';
  const analysisUrl = `${config.analysisServiceUrl}${endpoint}`;
  const allFindings = [];

  for (const fileItem of targetFiles) {
    const isDep = fileItem.isDependencyFile;
    if (detectorName === 'run_dependency_scan' && !isDep) continue;
    if (detectorName !== 'run_dependency_scan' && isDep) continue;

    let content = '';
    try {
      content = fs.readFileSync(fileItem.fullPath, 'utf8');
    } catch {
      continue;
    }

    const payload = isDep
      ? {
          filename: path.basename(fileItem.relPath),
          package_json_content: content,
          file_path: fileItem.relPath,
        }
      : {
          filename: path.basename(fileItem.relPath),
          content,
          file_path: fileItem.relPath,
        };

    try {
      const res = await fetch(analysisUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        const data = await res.json();
        const findings = data.findings || [];
        for (const f of findings) {
          allFindings.push({
            ...f,
            sourceFile: fileItem.relPath,
          });
        }
      }
    } catch (err) {
      console.warn(`[Planner] Detector ${detectorName} failed on ${fileItem.relPath}: ${err.message}`);
    }
  }

  return allFindings;
}

/**
 * Computes language and file statistics for the codebase
 */
export function computeCodebaseStats(targetFiles) {
  const languageStats = {};
  const fileTree = [];

  for (const f of targetFiles) {
    fileTree.push(f.relPath);
    const ext = f.ext || path.extname(f.relPath).toLowerCase();
    const lang = f.isDependencyFile ? 'dependency_manifest' : ext.replace('.', '') || 'unknown';
    languageStats[lang] = (languageStats[lang] || 0) + 1;
  }

  return { fileTree, languageStats };
}

/**
 * Planner Agent: uses Gemini function calling to decide which detectors to run.
 * Logs every tool call and its result.
 *
 * @param {Array<object>} targetFiles
 * @param {string} targetDir
 * @param {object} options
 * @param {function} [options.onTrace]
 * @returns {Promise<{ chosenTools: string[], findings: Array<object>, plannedBy: string }>}
 */
export async function runPlannerAgent(targetFiles, targetDir, options = {}) {
  const { onTrace } = options;
  const { fileTree, languageStats } = computeCodebaseStats(targetFiles);

  onTrace?.({
    agent: 'Planner',
    step: 'analyze_repository',
    tool: 'file_tree_inspection',
    input_summary: `${targetFiles.length} files detected: ${JSON.stringify(languageStats)}`,
    output_summary: 'Evaluating codebase composition to select static security analyzers',
    timestamp: new Date().toISOString(),
  });

  const model = config.geminiModel || 'gemini-1.5-flash';
  const apiKey = config.geminiApiKey;
  let chosenTools = [];
  let plannedBy = 'gemini';

  // Attempt Gemini Function Calling if API key is present
  if (apiKey) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    const fileSample = fileTree.slice(0, 50).join('\n') + (fileTree.length > 50 ? `\n... (+${fileTree.length - 50} more files)` : '');
    const prompt = `You are CodeGuard's Security Planning Agent.
Review this codebase file tree and language statistics:

Languages:
${JSON.stringify(languageStats, null, 2)}

File Tree Sample:
${fileSample}

Select all relevant security analyzers that should run against this project by calling their respective functions.`;

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: prompt }] }],
          tools: PLANNER_TOOLS,
          tool_config: {
            function_calling_config: { mode: 'AUTO' }
          }
        }),
        signal: AbortSignal.timeout(12000),
      });

      if (res.ok) {
        const data = await res.json();
        const candidate = data.candidates?.[0]?.content?.parts || [];
        for (const part of candidate) {
          if (part.functionCall) {
            chosenTools.push({
              name: part.functionCall.name,
              args: part.functionCall.args || {}
            });
          }
        }
      }
    } catch (err) {
      console.warn(`[Planner Agent] Gemini function calling failed: ${err.message}. Using deterministic fallback.`);
    }
  }

  // Fallback if Gemini returned no tools or API failed/unconfigured
  if (chosenTools.length === 0) {
    plannedBy = 'rule_based_fallback';
    const hasSource = Object.keys(languageStats).some(k => ['js', 'ts', 'jsx', 'tsx', 'py', 'mjs', 'cjs'].includes(k));
    const hasDeps = Boolean(languageStats['dependency_manifest'] || fileTree.some(p => p.includes('package.json') || p.includes('requirements')));

    if (hasSource) {
      chosenTools.push({ name: 'run_secrets_scan', args: { reason: 'Source files detected' } });
      chosenTools.push({ name: 'run_sqli_scan', args: { reason: 'Database and backend files present' } });
      chosenTools.push({ name: 'run_xss_scan', args: { reason: 'Client or server template files present' } });
    }
    if (hasDeps) {
      chosenTools.push({ name: 'run_dependency_scan', args: { reason: 'Dependency manifest files detected' } });
    }

    onTrace?.({
      agent: 'Planner',
      step: 'fallback',
      tool: 'heuristic_planner',
      input_summary: `Language stats: ${JSON.stringify(languageStats)}`,
      output_summary: `Selected tools: ${chosenTools.map(t => t.name).join(', ')}`,
      timestamp: new Date().toISOString(),
    });
  }

  // Execute chosen tools and log each call and result
  const rawFindings = [];
  const toolNames = [];

  for (const tool of chosenTools) {
    toolNames.push(tool.name);
    onTrace?.({
      agent: 'Planner',
      step: 'tool_call',
      tool: tool.name,
      input_summary: JSON.stringify(tool.args || {}),
      output_summary: `Invoking ${tool.name} on analysis service`,
      timestamp: new Date().toISOString(),
    });

    const findings = await executeDetector(tool.name, targetFiles, targetDir);
    rawFindings.push(...findings);

    onTrace?.({
      agent: 'Planner',
      step: 'tool_result',
      tool: tool.name,
      input_summary: tool.name,
      output_summary: `Completed ${tool.name}: discovered ${findings.length} raw findings`,
      timestamp: new Date().toISOString(),
    });
  }

  return {
    chosenTools: toolNames,
    findings: rawFindings,
    plannedBy,
  };
}
