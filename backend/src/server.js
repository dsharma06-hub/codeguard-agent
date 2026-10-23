import app from './app.js';
import { config } from './config/env.js';

const server = app.listen(config.port, () => {
  console.log(`[CodeGuard Backend] Server running in ${config.nodeEnv} mode on http://localhost:${config.port}`);
});

// Graceful shutdown handling
const handleShutdown = (signal) => {
  console.log(`\n[CodeGuard Backend] Received ${signal}. Closing server gracefully...`);
  server.close(() => {
    console.log('[CodeGuard Backend] HTTP server closed.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));
