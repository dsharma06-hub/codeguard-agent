import { Router } from 'express';

const router = Router();

/**
 * @route   GET /health
 * @desc    Basic service liveness check
 * @access  Public
 */
router.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

export default router;
