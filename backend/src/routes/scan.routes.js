import { Router } from 'express';
import multer from 'multer';
import { config } from '../config/env.js';
import { scanZipArchive, scanGitRepository, ScanServiceError } from '../services/scanService.js';
import { explainFinding, getFindingById, registerScanFindings } from '../services/llmExplanationService.js';
import { getSessionFromRequest } from '../services/authService.js';
import {
  subscribeAgentTrace,
  approveFix,
  rejectFix,
  getScanFixes,
} from '../../agents/orchestrator.js';
import { fixesStore } from '../../agents/fixAgent.js';

const router = Router();

// Configure multer memory storage with upload file size limit (default 100MB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxUploadSizeBytes,
    files: 1,
  },
});

/**
 * Middleware handling multer errors such as file size limit
 */
function handleUploadMiddleware(req, res, next) {
  const singleUpload = upload.single('file');
  singleUpload(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          error: `File size exceeds ${config.maxUploadSizeMb}MB limit.`,
        });
      }
      return res.status(400).json({
        error: `Upload error: ${err.message}`,
      });
    }
    next();
  });
}

/**
 * @route   POST /api/scan/upload
 * @desc    Upload a zip archive to extract, analyze, and return aggregated security findings
 * @access  Public
 */
router.post('/api/scan/upload', handleUploadMiddleware, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: 'No file uploaded. Please upload a .zip repository archive using field "file".',
      });
    }

    const originalName = req.file.originalname || 'archive.zip';
    if (!originalName.toLowerCase().endsWith('.zip') && req.file.mimetype !== 'application/zip' && req.file.mimetype !== 'application/x-zip-compressed') {
      return res.status(400).json({
        error: 'Invalid file type. Only .zip archives are supported.',
      });
    }

    const result = await scanZipArchive(req.file.buffer, originalName);
    return res.status(200).json(result);
  } catch (err) {
    if (err instanceof ScanServiceError) {
      return res.status(err.statusCode).json({
        error: err.message,
      });
    }

    console.error('Unhandled scan upload error:', err);
    return res.status(500).json({
      error: 'An unexpected internal error occurred while processing scan.',
    });
  }
});

/**
 * @route   POST /api/scan/repo
 * @desc    Clone a public GitHub repository and scan for security vulnerabilities
 * @access  Public
 */
router.post('/api/scan/repo', async (req, res) => {
  try {
    const { repoUrl } = req.body || {};
    if (!repoUrl) {
      return res.status(400).json({
        error: 'Missing required parameter "repoUrl".',
      });
    }

    const session = getSessionFromRequest(req);
    const accessToken = session?.accessToken || null;

    const result = await scanGitRepository(repoUrl, { accessToken });
    return res.status(200).json(result);
  } catch (err) {
    if (err instanceof ScanServiceError) {
      return res.status(err.statusCode).json({
        error: err.message,
      });
    }

    console.error('Unhandled repo scan error:', err);
    return res.status(500).json({
      error: 'An unexpected internal error occurred while scanning repository.',
    });
  }
});

/**
 * @route   POST /api/findings/:findingId/explain
 * @desc    Generate an on-demand AI explanation for a finding with automatic static fallback
 * @access  Public
 */
router.post('/api/findings/:findingId/explain', async (req, res) => {
  try {
    const { findingId } = req.params;
    const { finding: providedFinding, bypassCache, timeoutMs, customApiKey } = req.body || {};

    let finding = providedFinding || getFindingById(findingId);

    // If finding details were provided in request body, register them in session store
    if (providedFinding) {
      registerScanFindings([providedFinding]);
    }

    if (!finding) {
      return res.status(404).json({
        error: `Finding '${findingId}' not found in current session. Pass the finding object in the request body.`,
      });
    }

    const explanationResult = await explainFinding(finding, {
      bypassCache: Boolean(bypassCache),
      timeoutMs: typeof timeoutMs === 'number' ? timeoutMs : 8000,
      customApiKey,
    });

    return res.status(200).json(explanationResult);
  } catch (err) {
    console.error(`[Explain Route] Failed on finding ${req.params.findingId}:`, err);
    // Never fail the request — return fallback guidance with status 200
    const staticGuidance =
      req.body?.finding?.remediation ||
      'Apply proper input validation, sanitization, and follow framework security best practices.';
    return res.status(200).json({
      success: true,
      findingId: req.params.findingId,
      explanation: staticGuidance,
      isFallback: true,
      fallbackReason: 'internal_error',
      model: null,
      cached: false,
    });
  }
});

/**
 * @route   GET /api/scan/:id/agent-trace
 * @desc    Server-Sent Events (SSE) streaming endpoint for live agent execution traces
 * @access  Public
 */
router.get('/api/scan/:id/agent-trace', (req, res) => {
  const { id } = req.params;
  subscribeAgentTrace(id, res);
});

/**
 * @route   POST /api/fixes/:id/approve
 * @desc    Human-in-the-loop: Approve and apply a proposed fix to the ephemeral codebase copy
 * @access  Public
 */
router.post('/api/fixes/:id/approve', (req, res) => {
  try {
    const result = approveFix(req.params.id);
    return res.status(200).json(result);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

/**
 * @route   POST /api/fixes/:id/reject
 * @desc    Human-in-the-loop: Reject a proposed fix
 * @access  Public
 */
router.post('/api/fixes/:id/reject', (req, res) => {
  try {
    const result = rejectFix(req.params.id);
    return res.status(200).json(result);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

/**
 * @route   GET /api/fixes
 * @desc    List all proposed fixes across scans
 * @access  Public
 */
router.get('/api/fixes', (req, res) => {
  const fixes = Array.from(fixesStore.values());
  return res.status(200).json({ fixes });
});

/**
 * @route   GET /api/scan/:id/fixes
 * @desc    List all proposed fixes for a given scanId
 * @access  Public
 */
router.get('/api/scan/:id/fixes', (req, res) => {
  const fixes = getScanFixes(req.params.id);
  return res.status(200).json({ fixes });
});

/**
 * @route   GET /api/fixes/:id
 * @desc    Get details of a single proposed fix by ID
 * @access  Public
 */
router.get('/api/fixes/:id', (req, res) => {
  const fix = fixesStore.get(req.params.id);
  if (!fix) {
    return res.status(404).json({ error: `Fix '${req.params.id}' not found` });
  }
  return res.status(200).json({ fix });
});

export default router;

