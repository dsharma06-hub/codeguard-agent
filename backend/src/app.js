import express from 'express';
import cors from 'cors';
import { config } from './config/env.js';
import healthRoutes from './routes/health.routes.js';
import statusRoutes from './routes/status.routes.js';
import scanRoutes from './routes/scan.routes.js';
import authRoutes from './routes/auth.routes.js';
import githubRoutes from './routes/github.routes.js';
import { errorHandler } from './middleware/errorHandler.js';

const app = express();

const allowedOrigins = [
  config.frontendUrl,
  'http://localhost:5173',
  'http://127.0.0.1:5173',
].filter(Boolean);

// Core middlewares with explicit origin handling (not wildcard *) for cookie credentials
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. server-to-server, curl, tests)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      // Allow any localhost/127.0.0.1 port during local development
      if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
        return callback(null, true);
      }
      return callback(new Error(`Origin ${origin} not allowed by CORS`));
    },
    credentials: true,
  })
);
app.use(express.json());

// API routes
app.use(healthRoutes);
app.use(statusRoutes);
app.use(scanRoutes);
app.use(authRoutes);
app.use(githubRoutes);

// Fallback 404 handler for undefined routes
app.use((req, res) => {
  res.status(404).json({
    error: {
      message: `Cannot ${req.method} ${req.originalUrl}`
    }
  });
});

// Centralized error handling
app.use(errorHandler);

export default app;
