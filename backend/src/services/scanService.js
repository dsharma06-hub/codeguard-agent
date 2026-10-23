import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import AdmZip from 'adm-zip';
import { simpleGit } from 'simple-git';
import { config } from '../config/env.js';
import { buildAttackGraph } from './graphService.js';
import { registerScanFindings } from './llmExplanationService.js';
import { runAgenticOrchestrator, activeScansStore } from '../../agents/orchestrator.js';

const MAX_FILES = config.maxFiles || 2000;
const MAX_TOTAL_UNCOMPRESSED_BYTES = config.maxUncompressedSizeBytes || 500 * 1024 * 1024; // 500MB
const MAX_COMPRESSION_RATIO = 100;
const MIN_SIZE_FOR_RATIO_CHECK = 1024 * 1024; // 1MB uncompressed
const TARGET_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.pyw']);

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  '.next',
  '.nuxt',
  'coverage',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  '.pytest_cache',
  'site-packages',
  '.idea',
  '.vscode',
  'vendor',
  'target',
]);

const SKIPPED_FILE_EXTENSIONS = new Set([
  // Images
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svg', '.bmp', '.tiff', '.tif', '.avif', '.psd',
  // Fonts
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  // Audio & Video
  '.mp4', '.webm', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a',
  // Archives & Binaries
  '.zip', '.tar', '.gz', '.tgz', '.7z', '.rar', '.bz2', '.xz', '.exe', '.dll', '.so', '.dylib', '.bin', '.iso', '.dmg',
  // Bytecode & Compiled
  '.pyc', '.pyo', '.pyd', '.class', '.jar', '.war', '.ear', '.wasm',
  // Databases / Maps
  '.sqlite', '.sqlite3', '.db', '.map',
  // Documents
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
]);

const LOCK_FILENAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'poetry.lock',
  'pipfile.lock',
  'composer.lock',
  'cargo.lock',
  'gemfile.lock',
]);

/**
 * Determines whether a relative file/folder entry should be ignored
 * from file counting, extraction, and static analysis.
 *
 * @param {string} relPath - Relative path inside repository or zip archive
 * @returns {boolean}
 */
export function isIgnoredEntryPath(relPath) {
  if (!relPath || typeof relPath !== 'string') return true;

  const normalized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  const segments = normalized.split('/').filter(Boolean);
  if (segments.length === 0) return true;

  // Check if any directory segment is an ignored directory
  for (let i = 0; i < segments.length - 1; i++) {
    const seg = segments[i].toLowerCase();
    if (IGNORED_DIRS.has(seg) || seg.endsWith('.egg-info')) {
      return true;
    }
  }

  const lastSegment = segments[segments.length - 1];
  const lowerLast = lastSegment.toLowerCase();

  // If the last segment is an ignored directory
  if (IGNORED_DIRS.has(lowerLast) || lowerLast.endsWith('.egg-info')) {
    return true;
  }

  // Check for lock files
  if (LOCK_FILENAMES.has(lowerLast) || lowerLast.endsWith('.lock') || lowerLast.endsWith('.lockb')) {
    return true;
  }

  // Check for minified JavaScript/CSS
  if (
    lowerLast.endsWith('.min.js') ||
    lowerLast.endsWith('.min.mjs') ||
    lowerLast.endsWith('.min.cjs') ||
    lowerLast.endsWith('.min.css')
  ) {
    return true;
  }

  // Check for binary and non-source file extensions
  const ext = path.extname(lowerLast);
  if (ext && SKIPPED_FILE_EXTENSIONS.has(ext)) {
    return true;
  }

  return false;
}

/**
 * Custom error class for scan service errors
 */
export class ScanServiceError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = 'ScanServiceError';
    this.statusCode = statusCode;
  }
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
 * Maps analysis-service category/rule to frontend FindingCategory
 */
function mapCategory(ruleId = '', category = '') {
  const upperRule = ruleId.toUpperCase();
  const upperCat = category.toUpperCase();

  if (upperRule.includes('SECRET') || upperCat.includes('SECRET')) {
    return 'secret';
  }
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
    upperCat.includes('AI ANTIPATTERN') ||
    upperCat.includes('AI-ANTIPATTERN') ||
    upperRule.includes('RATE_LIMIT') ||
    upperRule.includes('ENDPOINT')
  ) {
    return 'ai-antipattern';
  }
  return 'validation';
}

/**
 * Builds code snippet context around finding
 */
function buildCodeSnippet(fileContent, finding, relPath) {
  const lines = fileContent.split(/\r?\n/);
  const targetStart = Math.max(1, finding.line_number || 1);
  const targetEnd = Math.max(targetStart, finding.end_line_number || targetStart);

  const contextBefore = 3;
  const contextAfter = 3;

  const startLine = Math.max(1, targetStart - contextBefore);
  const endLine = Math.min(lines.length, targetEnd + contextAfter);

  const snippetLines = lines.slice(startLine - 1, endLine);

  const highlightLines = [];
  for (let l = targetStart; l <= targetEnd; l++) {
    if (l >= startLine && l <= endLine) {
      highlightLines.push(l);
    }
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
 * Recursively traverses a directory collecting target files
 */
function collectTargetFiles(dirPath, baseDir = dirPath) {
  const results = [];
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name.toLowerCase()) || entry.name.endsWith('.egg-info')) {
        continue;
      }
      results.push(...collectTargetFiles(fullPath, baseDir));
    } else if (entry.isFile()) {
      if (isIgnoredEntryPath(relPath)) {
        continue;
      }
      const ext = path.extname(entry.name).toLowerCase();
      const lowerName = entry.name.toLowerCase();
      const isPackageJson = lowerName === 'package.json';
      const isRequirementsTxt = lowerName.includes('requirements') && ext === '.txt';
      const isPyProjectToml = lowerName === 'pyproject.toml';
      const isDependencyFile = isPackageJson || isRequirementsTxt || isPyProjectToml;

      if (TARGET_EXTENSIONS.has(ext) || isDependencyFile) {
        results.push({
          fullPath,
          relPath,
          isPackageJson,
          isDependencyFile,
          ext,
        });
      }
    }
  }

  return results;
}

/**
 * Validates and parses GitHub repository URL or slug
 * Supports https://github.com/owner/repo, http://github.com/owner/repo, or owner/repo shorthand
 *
 * @param {string} input - Repository URL or owner/repo shorthand
 * @returns {{ owner: string, repo: string, fullName: string, cloneUrl: string }}
 */
export function parseGitHubRepoUrl(input) {
  if (typeof input !== 'string') {
    throw new ScanServiceError('Repository URL must be a string.', 400);
  }

  const trimmed = input.trim();
  if (!trimmed) {
    throw new ScanServiceError('Repository URL cannot be empty.', 400);
  }

  // Reject shell metacharacters and leading command-line flags
  if (trimmed.startsWith('-') || /[\s\0\r\n;|<>&`$]/.test(trimmed)) {
    throw new ScanServiceError('Repository URL contains invalid characters or command flags.', 400);
  }

  let owner = '';
  let repo = '';

  if (/^https?:\/\//i.test(trimmed)) {
    let parsedUrl;
    try {
      parsedUrl = new URL(trimmed);
    } catch {
      throw new ScanServiceError('Invalid repository URL format.', 400);
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    if (hostname !== 'github.com' && hostname !== 'www.github.com') {
      throw new ScanServiceError('Only public GitHub repositories (github.com) are currently supported.', 400);
    }

    const pathParts = parsedUrl.pathname.split('/').filter(Boolean);
    if (pathParts.length < 2) {
      throw new ScanServiceError('Invalid GitHub repository path. Expected format: https://github.com/owner/repo', 400);
    }

    owner = pathParts[0];
    repo = pathParts[1].replace(/\.git$/i, '');
  } else {
    const parts = trimmed.split('/');
    if (parts.length !== 2) {
      throw new ScanServiceError('Invalid repository shorthand. Expected format: owner/repo (e.g. expressjs/express)', 400);
    }
    owner = parts[0];
    repo = parts[1].replace(/\.git$/i, '');
  }

  const ownerRegex = /^[a-zA-Z0-9_-]+$/;
  const repoRegex = /^[a-zA-Z0-9_.-]+$/;

  if (!ownerRegex.test(owner) || !repoRegex.test(repo) || repo === '.' || repo === '..') {
    throw new ScanServiceError(`Invalid GitHub repository slug: '${owner}/${repo}'.`, 400);
  }

  return {
    owner,
    repo,
    fullName: `${owner}/${repo}`,
    cloneUrl: `https://github.com/${owner}/${repo}.git`,
  };
}

/**
 * Shared scan pipeline: processes an extracted codebase directory, runs analysis microservice,
 * aggregates findings, and builds attack-path graph.
 *
 * @param {string} targetDir - Absolute path to folder containing codebase files
 * @param {Object} context - Metadata context { repoName, branch, commitHash, startTime, scanId }
 * @returns {Promise<Object>} Aggregated scan results matching frontend Finding format
 */
async function processDirectoryScan(targetDir, { repoName, branch = 'main', commitHash, startTime, scanId, useAgentic = true }) {
  const targetFiles = collectTargetFiles(targetDir);

  if (targetFiles.length > MAX_FILES) {
    throw new ScanServiceError(
      `Repository exceeds maximum limit of ${MAX_FILES} eligible source files (found ${targetFiles.length} files after ignoring node_modules/.git/etc.).`,
      400
    );
  }

  let totalLinesAnalyzed = 0;
  let findings = [];

  // If no scannable files found, return empty results immediately (valid 200 OK)
  if (targetFiles.length === 0) {
    const durationMs = Date.now() - startTime;
    return {
      metadata: {
        scanId,
        repoName,
        branch,
        commitHash: commitHash || scanId.slice(-7),
        scanTimestamp: new Date().toISOString(),
        durationMs,
        filesScanned: 0,
        linesAnalyzed: 0,
      },
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      findings: [],
      graph: {
        nodes: [],
        edges: [],
      },
    };
  }

  // Test analysis-service health before batch processing or agentic orchestration
  try {
    const healthController = new AbortController();
    const healthTimeout = setTimeout(() => healthController.abort(), 2500);
    const healthRes = await fetch(`${config.analysisServiceUrl}/health`, {
      signal: healthController.signal,
    });
    clearTimeout(healthTimeout);
    if (!healthRes.ok) {
      throw new Error(`Health check returned status ${healthRes.status}`);
    }
  } catch (err) {
    throw new ScanServiceError(
      'Analysis microservice is unreachable. Please verify analysis-service is running on port 8000.',
      503
    );
  }

  // Use agentic orchestrator (Planner -> Detectors -> Verifier -> FixAgent)
  if (useAgentic !== false) {
    try {
      return await runAgenticOrchestrator(targetDir, targetFiles, {
        scanId,
        repoName,
        branch,
        commitHash,
        startTime,
      });
    } catch (agentErr) {
      console.warn(`[ScanService] Agentic orchestrator failed: ${agentErr.message}. Falling back to static scan.`);
    }
  }

  // Pre-check for repo-level rate-limiting mechanisms in package.json
  let repoHasRateLimiting = false;
  for (const fileItem of targetFiles) {
    if (fileItem.isPackageJson) {
      try {
        const pkgContent = fs.readFileSync(fileItem.fullPath, 'utf-8');
        const pkg = JSON.parse(pkgContent);
        const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
        if (
          allDeps['express-rate-limit'] ||
          allDeps['express-slow-down'] ||
          allDeps['rate-limiter-flexible'] ||
          allDeps['express-brute']
        ) {
          repoHasRateLimiting = true;
        }
      } catch {}
    }
  }

  // Send each target file to analysis-service
  let findingIndex = 1;
  for (const fileItem of targetFiles) {
    const content = fs.readFileSync(fileItem.fullPath, 'utf-8');
    const linesInFile = content.split(/\r?\n/).length;
    totalLinesAnalyzed += linesInFile;

    const payload = {
      filename: fileItem.relPath,
      content: content,
    };

    if (fileItem.isPackageJson) {
      payload.packageJsonContent = content;
    }

    let res;
    try {
      const analyzeController = new AbortController();
      const analyzeTimeout = setTimeout(() => analyzeController.abort(), 10000);

      res = await fetch(`${config.analysisServiceUrl}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: analyzeController.signal,
      });
      clearTimeout(analyzeTimeout);
    } catch (err) {
      throw new ScanServiceError(
        `Analysis service request failed during scan of ${fileItem.relPath}: ${err.message}`,
        502
      );
    }

    if (!res.ok) {
      const errorText = await res.text();
      throw new ScanServiceError(
        `Analysis service error (${res.status}) on ${fileItem.relPath}: ${errorText}`,
        502
      );
    }

    const resultData = await res.json();
    if (resultData.has_rate_limiting) {
      repoHasRateLimiting = true;
    }
    const serviceFindings = resultData.findings || [];

    for (const rawFinding of serviceFindings) {
      const severity = (rawFinding.severity || 'low').toLowerCase();
      const category = mapCategory(rawFinding.rule_id, rawFinding.category);
      const codeSnippet = buildCodeSnippet(content, rawFinding, fileItem.relPath);
      const catPrefix = category === 'ai-antipattern' ? 'ant' : category.slice(0, 3);

      findings.push({
        id: `cg-${catPrefix}-${String(findingIndex++).padStart(3, '0')}`,
        title: rawFinding.title || 'Security Finding',
        severity: severity === 'info' ? 'low' : severity,
        category,
        filePath: fileItem.relPath,
        startLine: rawFinding.line_number,
        endLine: rawFinding.end_line_number || rawFinding.line_number,
        description: rawFinding.description || '',
        remediation: rawFinding.remediation || '',
        cwe: rawFinding.cwe_id || undefined,
        codeSnippet,
        sourceExpression: rawFinding.source_expression || undefined,
        sourceLine: rawFinding.source_line || undefined,
        sinkExpression: rawFinding.sink_expression || undefined,
        sinkLine: rawFinding.sink_line || undefined,
      });
    }
  }

  // Post-aggregation step: Pattern 1 False Positive Guard
  // If rate limiting is found anywhere in the repo, suppress all missing rate-limiting findings
  if (repoHasRateLimiting) {
    findings = findings.filter(
      (f) => !(f.category === 'ai-antipattern' && f.cwe === 'CWE-307')
    );
  }

  const durationMs = Date.now() - startTime;

  // Calculate summary counts
  const summary = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };

  // Synthesize attack-path graph from findings
  const graph = buildAttackGraph(findings);

  // Register findings in LLM explanation session store for on-demand lookups
  registerScanFindings(findings);

  return {
    metadata: {
      repoName,
      branch,
      commitHash: commitHash || scanId.slice(-7),
      scanTimestamp: new Date().toISOString(),
      durationMs,
      filesScanned: targetFiles.length,
      linesAnalyzed: totalLinesAnalyzed,
    },
    summary,
    findings,
    graph,
  };
}

/**
 * Recursively removes read-only attributes from files and directories to ensure deletion succeeds
 */
function makeWritableRecursively(dirPath) {
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      try {
        fs.chmodSync(fullPath, 0o666);
      } catch {}
      if (entry.isDirectory()) {
        makeWritableRecursively(fullPath);
      }
    }
  } catch {}
}

/**
 * Sweeps any orphaned temporary scan directories in tempBaseDir older than 2 minutes
 */
function cleanupStaleScanDirs(tempBaseDir) {
  try {
    if (!fs.existsSync(tempBaseDir)) return;
    const now = Date.now();
    const entries = fs.readdirSync(tempBaseDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && (entry.name.startsWith('scan_') || entry.name.startsWith('git_'))) {
        const fullPath = path.join(tempBaseDir, entry.name);
        try {
          const stat = fs.statSync(fullPath);
          if (now - stat.mtimeMs > 10 * 1000) {
            makeWritableRecursively(fullPath);
            fs.rmSync(fullPath, { recursive: true, force: true });
          }
        } catch {}
      }
    }
  } catch {}
}

/**
 * Safely removes a temporary directory with retries, attribute unlocking, and native fallbacks
 * to handle Windows transient file locks and read-only attributes.
 */
async function safeCleanDirectory(targetDir) {
  if (!targetDir || !fs.existsSync(targetDir)) {
    return;
  }

  // Ensure files and directories are writable (clearing git packfile/venv readonly flags)
  makeWritableRecursively(targetDir);

  // Attempt 1: Async Node.js removal with generous retries (20 retries * 150ms = 3.0s window)
  try {
    await fs.promises.rm(targetDir, {
      recursive: true,
      force: true,
      maxRetries: 20,
      retryDelay: 150,
    });
  } catch (rmErr) {
    // Non-fatal yet: proceed to native fallback
  }

  // Check if directory was successfully removed
  if (!fs.existsSync(targetDir)) {
    return;
  }

  // Attempt 2: On Windows, use native kernel cmd.exe rd /s /q as authoritative fallback
  if (process.platform === 'win32') {
    try {
      const { spawnSync } = await import('child_process');
      spawnSync('cmd.exe', ['/c', 'rd', '/s', '/q', targetDir], {
        stdio: 'ignore',
        timeout: 5000,
      });
    } catch {}
  }

  // Attempt 3: Brief delay for deferred NTFS handle release followed by final rmSync
  if (fs.existsSync(targetDir)) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    try {
      makeWritableRecursively(targetDir);
      fs.rmSync(targetDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } catch (cleanupErr) {
      console.error(`Failed to clean up temp scan directory ${targetDir}:`, cleanupErr);
    }
  }
}

/**
 * Orchestrates security scan on uploaded zip archive buffer or path
 *
 * @param {Buffer} zipBuffer - In-memory zip file buffer
 * @param {string} originalName - Original uploaded filename
 * @returns {Promise<Object>} Aggregated scan results matching frontend Finding format
 */
export async function scanZipArchive(zipBuffer, originalName = 'uploaded-repo.zip') {
  const startTime = Date.now();
  const scanId = `scan_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
  const tempExtractDir = path.join(tempBaseDir, scanId);
  const normalizedTargetDir = path.resolve(tempExtractDir);

  cleanupStaleScanDirs(tempBaseDir);

  try {
    // 1. Validate zip archive integrity
    let zip;
    try {
      zip = new AdmZip(zipBuffer);
    } catch (err) {
      throw new ScanServiceError('Invalid or corrupted zip archive file.', 400);
    }

    const zipEntries = zip.getEntries();
    if (!zipEntries || zipEntries.length === 0) {
      throw new ScanServiceError('Zip archive is empty.', 400);
    }

    // 2. Validate entries for path traversal / zip slip and zip bombs across all entries,
    // and filter out ignored files and directories from counting, extraction, and sizing
    let totalEligibleUncompressedBytes = 0;
    const eligibleEntries = [];
    let totalRawFiles = 0;

    for (const entry of zipEntries) {
      const entryName = entry.entryName;

      // Reject null bytes or Windows drive specifiers in entry name
      if (entryName.includes('\0') || /^[a-zA-Z]:/.test(entryName)) {
        throw new ScanServiceError(
          `Zip slip detected: invalid characters or drive path in entry '${entryName}'.`,
          400
        );
      }

      // Canonical path resolution check: guarantee resolved path stays inside extraction directory
      const resolvedPath = path.resolve(normalizedTargetDir, entryName);
      if (!resolvedPath.startsWith(normalizedTargetDir + path.sep) && resolvedPath !== normalizedTargetDir) {
        throw new ScanServiceError(
          `Zip slip / path traversal detected: entry '${entryName}' escapes the extraction directory.`,
          400
        );
      }

      const isDir = entry.isDirectory || entryName.endsWith('/') || entryName.endsWith('\\');
      if (!isDir) {
        totalRawFiles++;
      }

      // Zip bomb compression ratio check (>100:1 ratio on significant payload)
      if (entry.header.compressedSize > 0 && entry.header.size > MIN_SIZE_FOR_RATIO_CHECK) {
        const ratio = entry.header.size / entry.header.compressedSize;
        if (ratio > MAX_COMPRESSION_RATIO) {
          throw new ScanServiceError(
            `Zip bomb detected: compression ratio (${Math.round(ratio)}:1) exceeds safe limit for entry '${entryName}'.`,
            400
          );
        }
      }

      // Filter out ignored paths so dependencies (node_modules, vendor, etc.), build artifacts,
      // and binaries are neither counted against the file limit nor extracted
      if (isIgnoredEntryPath(entryName)) {
        continue;
      }

      // Skip directory entries from extraction list (directories are created recursively when writing files)
      if (isDir) {
        continue;
      }

      totalEligibleUncompressedBytes += entry.header.size;
      if (totalEligibleUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
        throw new ScanServiceError(
          `Zip archive uncompressed content exceeds safety limit of ${Math.round(MAX_TOTAL_UNCOMPRESSED_BYTES / (1024 * 1024))}MB.`,
          400
        );
      }

      eligibleEntries.push({ entry, resolvedPath });
    }

    // 3. Enforce file-count limit on eligible (non-ignored) files
    if (eligibleEntries.length > MAX_FILES) {
      throw new ScanServiceError(
        `Zip archive exceeds maximum limit of ${MAX_FILES} files (found ${eligibleEntries.length} files after ignoring node_modules/.git/etc., total ${totalRawFiles || zipEntries.length} in archive).`,
        400
      );
    }

    // 4. Extract ONLY eligible non-ignored files to temporary folder
    fs.mkdirSync(normalizedTargetDir, { recursive: true });
    for (const { entry, resolvedPath } of eligibleEntries) {
      fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
      fs.writeFileSync(resolvedPath, entry.getData());
    }

    // 4. Run directory scan pipeline
    const scanResult = await processDirectoryScan(normalizedTargetDir, {
      repoName: originalName.replace(/\.zip$/i, ''),
      branch: 'main',
      commitHash: scanId.slice(-7),
      startTime,
      scanId,
    });

    // Retain ephemeral copy in dedicated folder for human-in-the-loop patch approval
    try {
      const ephemeralBaseDir = path.join(os.tmpdir(), 'codeguard-ephemeral');
      const ephemeralTargetDir = path.join(ephemeralBaseDir, scanId);
      fs.mkdirSync(ephemeralBaseDir, { recursive: true });
      fs.cpSync(normalizedTargetDir, ephemeralTargetDir, { recursive: true });
      if (activeScansStore.has(scanId)) {
        activeScansStore.get(scanId).targetDir = ephemeralTargetDir;
      }
    } catch {}

    return scanResult;
  } finally {
    // 5. Always ensure temporary directory cleanup
    await safeCleanDirectory(normalizedTargetDir);
  }

}

/**
 * Clones a public GitHub repository using shallow clone and runs security analysis
 *
 * @param {string} repoUrl - GitHub repository URL or slug (e.g. "expressjs/cors" or "https://github.com/expressjs/cors")
 * @returns {Promise<Object>} Aggregated scan results matching frontend Finding format
 */
export async function scanGitRepository(repoUrl, options = {}) {
  const { accessToken = null } = options;
  const startTime = Date.now();
  const parsed = parseGitHubRepoUrl(repoUrl);
  const scanId = `git_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
  const tempExtractDir = path.join(tempBaseDir, scanId);
  const normalizedTargetDir = path.resolve(tempExtractDir);

  cleanupStaleScanDirs(tempBaseDir);

  try {
    fs.mkdirSync(normalizedTargetDir, { recursive: true });

    // Initialize simple-git with non-interactive execution and 30-second timeout
    const git = simpleGit({
      timeout: { block: 30000 },
    }).env({
      GIT_TERMINAL_PROMPT: '0',
      GCM_INTERACTIVE: 'never',
    });

    const cloneTargetUrl = accessToken
      ? `https://${encodeURIComponent(accessToken)}@github.com/${parsed.owner}/${parsed.repo}.git`
      : parsed.cloneUrl;

    try {
      await git.clone(cloneTargetUrl, normalizedTargetDir, [
        '--depth', '1',
        '--single-branch',
        '--no-tags',
      ]);
    } catch (gitErr) {
      let errMsg = gitErr.message || '';
      // Security: redact access token from error message if present
      if (accessToken) {
        errMsg = errMsg.split(accessToken).join('***');
        const encodedToken = encodeURIComponent(accessToken);
        if (encodedToken !== accessToken) {
          errMsg = errMsg.split(encodedToken).join('***');
        }
      }

      // Check timeout
      if (errMsg.includes('block') || errMsg.includes('timeout') || errMsg.includes('timed out')) {
        throw new ScanServiceError('Repository clone timed out after 30 seconds.', 408);
      }

      // Authenticated clone error handling
      if (accessToken) {
        if (
          errMsg.includes('Authentication failed') ||
          errMsg.includes('Permission denied') ||
          errMsg.includes('could not read Username') ||
          errMsg.includes('terminal prompts disabled')
        ) {
          throw new ScanServiceError(
            `Unable to clone repository '${parsed.fullName}'. Please check your GitHub permissions or re-authenticate.`,
            403
          );
        }
        if (errMsg.includes('not found') || errMsg.includes('Repository not found')) {
          throw new ScanServiceError(
            `GitHub repository '${parsed.fullName}' was not found or access was denied.`,
            404
          );
        }
      } else {
        // Anonymous clone error handling: fast HEAD check to distinguish 404 from 403
        try {
          const checkRes = await fetch(`https://github.com/${parsed.owner}/${parsed.repo}`, {
            method: 'HEAD',
            headers: { 'User-Agent': 'CodeGuard-Scanner' },
            signal: AbortSignal.timeout(4000),
          });
          if (checkRes.status === 404) {
            throw new ScanServiceError(
              `GitHub repository '${parsed.fullName}' was not found. Please verify the owner and repository name.`,
              404
            );
          }
        } catch (checkErr) {
          if (checkErr instanceof ScanServiceError) throw checkErr;
        }

        if (
          errMsg.includes('terminal prompts disabled') ||
          errMsg.includes('could not read Username') ||
          errMsg.includes('interactivity has been disabled') ||
          errMsg.includes('Authentication failed') ||
          errMsg.includes('Permission denied')
        ) {
          throw new ScanServiceError(
            `Repository '${parsed.fullName}' is private or requires authentication. CodeGuard currently only supports public repositories.`,
            403
          );
        }
      }

      throw new ScanServiceError(`Failed to clone GitHub repository '${parsed.fullName}': ${errMsg}`, 400);
    }

    // Attempt to extract branch and commit hash from cloned git metadata
    let branch = 'main';
    let commitHash = scanId.slice(-7);
    try {
      const headFile = path.join(normalizedTargetDir, '.git', 'HEAD');
      if (fs.existsSync(headFile)) {
        const headContent = fs.readFileSync(headFile, 'utf-8').trim();
        if (headContent.startsWith('ref: refs/heads/')) {
          branch = headContent.replace('ref: refs/heads/', '');
        }
      }
      const fetchHeadFile = path.join(normalizedTargetDir, '.git', 'FETCH_HEAD');
      if (fs.existsSync(fetchHeadFile)) {
        const fetchHeadContent = fs.readFileSync(fetchHeadFile, 'utf-8');
        const match = fetchHeadContent.match(/^([0-9a-f]{40})/i);
        if (match) {
          commitHash = match[1].slice(0, 7);
        }
      }
    } catch {
      // Non-critical: branch/commit metadata fallback
    }

    // Run directory scan pipeline
    return await processDirectoryScan(normalizedTargetDir, {
      repoName: parsed.fullName,
      branch,
      commitHash,
      startTime,
      scanId,
    });
  } finally {
    // Guaranteed cleanup of clone directory on success and failure
    await safeCleanDirectory(normalizedTargetDir);
  }
}
