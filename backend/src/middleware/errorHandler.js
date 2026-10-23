import { config } from '../config/env.js';

/**
 * Global error handling middleware.
 * Ensures consistent JSON error responses across all routes.
 */
export const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res.status(statusCode).json({
    error: {
      message,
      ...(config.nodeEnv === 'development' && { stack: err.stack })
    }
  });
};
