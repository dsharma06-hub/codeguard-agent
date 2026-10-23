import { Router } from 'express';
import { config } from '../config/env.js';

const router = Router();

/**
 * @route   GET /api/status
 * @desc    Aggregate service health check verifying backend & analysis microservice connectivity
 * @access  Public
 */
router.get('/api/status', async (req, res) => {
  let analysisServiceStatus = 'unreachable';

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000); // 2s timeout

    const response = await fetch(`${config.analysisServiceUrl}/health`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      if (data && data.status === 'ok') {
        analysisServiceStatus = 'ok';
      }
    }
  } catch (err) {
    analysisServiceStatus = 'unreachable';
  }

  res.status(200).json({
    backend: 'ok',
    analysisService: analysisServiceStatus,
    timestamp: new Date().toISOString(),
  });
});

export default router;
