import dotenv from 'dotenv';

dotenv.config();

export const config = {
  port: parseInt(process.env.PORT, 10) || 5000,
  analysisServiceUrl: process.env.ANALYSIS_SERVICE_URL || 'http://localhost:8000',
  nodeEnv: process.env.NODE_ENV || 'development',
  geminiApiKey: process.env.GEMINI_API_KEY || '',
  geminiModel: process.env.GEMINI_MODEL || 'gemini-3.5-flash-lite',
  githubClientId: process.env.GITHUB_CLIENT_ID || '',
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || '',
  githubRedirectUri: process.env.GITHUB_REDIRECT_URI || 'http://localhost:5000/api/auth/github/callback',
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
  maxUploadSizeMb: parseInt(process.env.MAX_UPLOAD_SIZE_MB, 10) || 100,
  maxUploadSizeBytes: (parseInt(process.env.MAX_UPLOAD_SIZE_MB, 10) || 100) * 1024 * 1024,
  maxFiles: parseInt(process.env.MAX_FILES, 10) || 2000,
  maxUncompressedSizeMb: parseInt(process.env.MAX_UNCOMPRESSED_SIZE_MB, 10) || 500,
  maxUncompressedSizeBytes: (parseInt(process.env.MAX_UNCOMPRESSED_SIZE_MB, 10) || 500) * 1024 * 1024,
  maxFixRetries: parseInt(process.env.MAX_FIX_RETRIES, 10) || 3,
};

