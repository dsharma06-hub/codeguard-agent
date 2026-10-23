import { config } from '../config/env.js';

/**
 * In-memory caches for current scan session
 */
const explanationCache = new Map();
const findingsStore = new Map();

/**
 * Register findings from a completed scan so they can be looked up on-demand
 * @param {Array<object>} findings
 */
export function registerScanFindings(findings = []) {
  if (!Array.isArray(findings)) return;
  for (const finding of findings) {
    if (finding && finding.id) {
      findingsStore.set(finding.id, finding);
    }
  }
}

/**
 * Retrieve a cached finding by ID
 * @param {string} findingId
 * @returns {object|null}
 */
export function getFindingById(findingId) {
  return findingsStore.get(findingId) || null;
}

/**
 * Clear session caches (useful for tests)
 */
export function clearExplanationCache() {
  explanationCache.clear();
  findingsStore.clear();
}

/**
 * Formats a concise prompt for Gemini to explain a finding in context
 * @param {object} finding
 * @returns {string}
 */
function buildPrompt(finding) {
  let snippetCode = '';
  if (finding.codeSnippet) {
    if (Array.isArray(finding.codeSnippet.lines)) {
      snippetCode = finding.codeSnippet.lines.join('\n');
    } else if (typeof finding.codeSnippet === 'string') {
      snippetCode = finding.codeSnippet;
    }
  }

  return `You are a senior application security engineer reviewing a code scan finding.
Explain why this vulnerability is dangerous in this specific context in 3 to 5 concise sentences, followed by a specific code fix tailored directly to the code shown (do not give generic advice).

Finding Details:
- Title: ${finding.title || 'Security Finding'}
- Category: ${finding.category || 'Security Risk'}
- CWE: ${finding.cwe || 'N/A'}
- File: ${finding.filePath || 'Source Code'}
- Vulnerable Code:
\`\`\`
${snippetCode}
\`\`\`

Format your response in two clear sections:
### Why It's Dangerous
(3-5 concise, plain-language sentences explaining the risk and impact in this specific context)

### How to Fix It
(A specific, drop-in replacement code snippet and 1-2 sentence explanation)`;
}

/**
 * Generates an LLM explanation for a security finding with automatic static fallback
 * @param {object} finding
 * @param {object} options
 * @param {boolean} [options.bypassCache=false]
 * @param {number} [options.timeoutMs=8000]
 * @param {string} [options.customApiKey]
 * @returns {Promise<{ success: boolean, findingId: string, explanation: string, isFallback: boolean, fallbackReason?: string, model?: string, cached?: boolean }>}
 */
export async function explainFinding(finding, options = {}) {
  const {
    bypassCache = false,
    timeoutMs = 8000,
    customApiKey = null,
  } = options;

  if (!finding || !finding.id) {
    throw new Error('Valid finding object with "id" is required.');
  }

  // Check in-memory cache first
  if (!bypassCache && explanationCache.has(finding.id)) {
    const cached = explanationCache.get(finding.id);
    return {
      ...cached,
      cached: true,
    };
  }

  const staticFallback =
    finding.remediation ||
    'Apply proper input validation, sanitization, and follow framework security best practices.';

  const apiKey = customApiKey !== null ? customApiKey : config.geminiApiKey;

  // Fallback immediately if API key is missing
  if (!apiKey || apiKey.trim() === '') {
    const fallbackResult = {
      success: true,
      findingId: finding.id,
      explanation: staticFallback,
      isFallback: true,
      fallbackReason: 'missing_key',
      model: null,
      cached: false,
    };
    explanationCache.set(finding.id, fallbackResult);
    return fallbackResult;
  }

  const model = config.geminiModel || 'gemini-3.5-flash-lite';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  const prompt = buildPrompt(finding);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 600,
        },
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      const status = res.status;
      const reason = status === 429 ? 'rate_limit' : 'api_error';
      console.warn(`[LLM Explanation] Gemini API returned status ${status} (${reason}), falling back to static guidance.`);
      const fallbackResult = {
        success: true,
        findingId: finding.id,
        explanation: staticFallback,
        isFallback: true,
        fallbackReason: reason,
        model: null,
        cached: false,
      };
      explanationCache.set(finding.id, fallbackResult);
      return fallbackResult;
    }

    const data = await res.json();
    const candidateText = data.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!candidateText || candidateText.trim() === '') {
      console.warn('[LLM Explanation] Gemini API returned empty candidate content, falling back to static guidance.');
      const fallbackResult = {
        success: true,
        findingId: finding.id,
        explanation: staticFallback,
        isFallback: true,
        fallbackReason: 'empty_response',
        model: null,
        cached: false,
      };
      explanationCache.set(finding.id, fallbackResult);
      return fallbackResult;
    }

    const result = {
      success: true,
      findingId: finding.id,
      explanation: candidateText.trim(),
      isFallback: false,
      fallbackReason: null,
      model,
      cached: false,
    };

    explanationCache.set(finding.id, result);
    return result;
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === 'AbortError';
    const reason = isTimeout ? 'timeout' : 'network_error';
    console.warn(`[LLM Explanation] Call failed (${reason}: ${err.message}), falling back to static guidance.`);

    const fallbackResult = {
      success: true,
      findingId: finding.id,
      explanation: staticFallback,
      isFallback: true,
      fallbackReason: reason,
      model: null,
      cached: false,
    };

    explanationCache.set(finding.id, fallbackResult);
    return fallbackResult;
  }
}
