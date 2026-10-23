import fs from 'fs';
import path from 'path';
import { config } from '../src/config/env.js';

/**
 * Extracts +/- 20 lines of surrounding code context around a finding
 */
export function extractSurroundingCode(fullFilePath, startLine, endLine) {
  try {
    if (!fs.existsSync(fullFilePath)) return '';
    const content = fs.readFileSync(fullFilePath, 'utf8');
    const lines = content.split(/\r?\n/);
    const startIdx = Math.max(0, (startLine || 1) - 21);
    const endIdx = Math.min(lines.length, (endLine || startLine || 1) + 20);
    return lines
      .slice(startIdx, endIdx)
      .map((line, idx) => `${startIdx + idx + 1}: ${line}`)
      .join('\n');
  } catch {
    return '';
  }
}

/**
 * Verifier Agent: evaluates each finding using Gemini with strict JSON output.
 * Filters out false positives with confidence >= 0.7 but keeps them in the report as "dismissed".
 *
 * @param {Array<object>} findings
 * @param {string} targetDir
 * @param {object} options
 * @param {function} [options.onTrace]
 * @returns {Promise<Array<object>>} Updated findings with verifier status & reasoning
 */
export async function runVerifierAgent(findings, targetDir, options = {}) {
  const { onTrace } = options;
  const verifiedFindings = [];
  const model = config.geminiModel || 'gemini-1.5-flash';
  const apiKey = config.geminiApiKey;

  onTrace?.({
    agent: 'Verifier',
    step: 'start_verification',
    tool: 'context_extractor',
    input_summary: `Reviewing ${findings.length} findings with surrounding context`,
    output_summary: 'Starting verification to filter out false positives',
    timestamp: new Date().toISOString(),
  });

  for (const finding of findings) {
    const fullPath = path.join(targetDir, finding.filePath);
    const surroundingContext = extractSurroundingCode(
      fullPath,
      finding.startLine,
      finding.endLine
    );

    let verdict = 'true_positive';
    let confidence = 0.85;
    let reasoning = 'Vulnerability confirmed in context.';

    if (apiKey) {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
      const prompt = `You are CodeGuard's Security Verifier Agent.
Analyze this static analysis finding and determine whether it is a real vulnerability (true_positive) or a false_positive (e.g. test dummy data, hardcoded sample in docs, already sanitized, unreachable code, or framework safe pattern).

Finding:
- Title: ${finding.title}
- Rule: ${finding.cwe || finding.category}
- File: ${finding.filePath}:${finding.startLine}
- Details: ${finding.description}

Surrounding Code (+/- 20 lines):
\`\`\`
${surroundingContext}
\`\`\`

Respond ONLY with valid JSON in this exact structure:
{
  "verdict": "true_positive" | "false_positive",
  "confidence": 0.95,
  "reasoning": "2-3 concise sentences explaining why this is a real vulnerability or false positive."
}`;

      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ role: 'user', parts: [{ text: prompt }] }],
            generationConfig: {
              temperature: 0.1,
              responseMimeType: 'application/json',
            },
          }),
          signal: AbortSignal.timeout(8000),
        });

        if (res.ok) {
          const data = await res.json();
          const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
          const parsed = JSON.parse(rawText);
          if (parsed.verdict === 'true_positive' || parsed.verdict === 'false_positive') {
            verdict = parsed.verdict;
            confidence = typeof parsed.confidence === 'number' ? Math.max(0, Math.min(1, parsed.confidence)) : 0.8;
            reasoning = parsed.reasoning || reasoning;
          }
        }
      } catch (err) {
        // Fallback: heuristic check for obvious test / sample code
        const isTestFile = /(test|mock|spec|fixture)/i.test(finding.filePath);
        if (isTestFile && finding.category === 'secret') {
          verdict = 'false_positive';
          confidence = 0.85;
          reasoning = 'Sample credential detected inside test/fixture file context.';
        }
      }
    } else {
      // Heuristic fallback when Gemini is offline
      const isTestFile = /(test|mock|spec|fixture)/i.test(finding.filePath);
      if (isTestFile && finding.category === 'secret') {
        verdict = 'false_positive';
        confidence = 0.85;
        reasoning = 'Credential in test fixture context identified as test dummy.';
      }
    }

    const isDismissed = verdict === 'false_positive' && confidence >= 0.7;

    const enriched = {
      ...finding,
      status: isDismissed ? 'dismissed' : 'verified',
      dismissed: isDismissed,
      dismissedReason: isDismissed ? reasoning : undefined,
      verifierConfidence: confidence,
      verifierReasoning: reasoning,
      verdict,
    };

    onTrace?.({
      agent: 'Verifier',
      step: 'verify_finding',
      tool: 'gemini_verifier',
      input_summary: `${finding.id} (${finding.title}) at ${finding.filePath}:${finding.startLine}`,
      output_summary: `${isDismissed ? 'DISMISSED (FP' : 'VERIFIED (TP'}, ${(confidence * 100).toFixed(0)}% conf): ${reasoning}`,
      timestamp: new Date().toISOString(),
    });

    verifiedFindings.push(enriched);
  }

  const dismissedCount = verifiedFindings.filter(f => f.status === 'dismissed').length;
  const activeCount = verifiedFindings.length - dismissedCount;

  onTrace?.({
    agent: 'Verifier',
    step: 'complete_verification',
    tool: 'verifier_summary',
    input_summary: `Reviewed ${verifiedFindings.length} findings`,
    output_summary: `Verification complete: ${activeCount} true positives confirmed, ${dismissedCount} false positives dismissed`,
    timestamp: new Date().toISOString(),
  });

  return verifiedFindings;
}
