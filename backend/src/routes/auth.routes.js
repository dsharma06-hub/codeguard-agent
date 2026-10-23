import { Router } from 'express';
import { config } from '../config/env.js';
import {
  createOAuthState,
  validateOAuthState,
  createSession,
  destroySession,
  extractSessionId,
  getSessionFromRequest,
  sanitizeUser,
  buildSessionCookie,
  buildClearCookie,
} from '../services/authService.js';

const router = Router();

/**
 * @route   GET /api/auth/github
 * @desc    Initiates GitHub OAuth flow by redirecting user to GitHub's authorize endpoint
 * @access  Public
 */
router.get('/api/auth/github', (req, res) => {
  if (!config.githubClientId) {
    return res.status(500).json({
      error: 'GitHub OAuth Client ID is not configured on the server.',
    });
  }

  const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : '';
  const state = createOAuthState(returnTo);

  const params = new URLSearchParams({
    client_id: config.githubClientId,
    redirect_uri: config.githubRedirectUri,
    scope: 'repo read:user user:email',
    state,
  });

  const authorizeUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;

  // Allow clients or tests to inspect the generated URL directly via ?format=json
  if (req.query.format === 'json') {
    return res.status(200).json({
      authorizeUrl,
      clientId: config.githubClientId,
      redirectUri: config.githubRedirectUri,
      scope: 'repo read:user user:email',
      state,
    });
  }

  return res.redirect(authorizeUrl);
});

/**
 * @route   GET /api/auth/github/callback
 * @desc    Handles OAuth callback from GitHub, exchanges authorization code for access token,
 *          and establishes an httpOnly cookie session
 * @access  Public
 */
router.get('/api/auth/github/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).json({
      error: error_description || error || 'GitHub authorization was declined.',
    });
  }

  if (!state || !validateOAuthState(state)) {
    return res.status(400).json({
      error: 'Invalid or expired OAuth state parameter (CSRF protection validation failed).',
    });
  }

  if (!code) {
    return res.status(400).json({
      error: 'Missing required authorization code from GitHub.',
    });
  }

  try {
    // 1. Exchange authorization code for access token via GitHub's OAuth token endpoint
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': 'CodeGuard-Scanner',
      },
      body: JSON.stringify({
        client_id: config.githubClientId,
        client_secret: config.githubClientSecret,
        code,
        redirect_uri: config.githubRedirectUri,
      }),
    });

    if (!tokenRes.ok) {
      return res.status(tokenRes.status).json({
        error: `GitHub token exchange failed with status ${tokenRes.status}.`,
      });
    }

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return res.status(401).json({
        error: tokenData.error_description || tokenData.error || 'Failed to obtain access token from GitHub.',
      });
    }

    const accessToken = tokenData.access_token;

    // 2. Fetch authenticated user profile
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'CodeGuard-Scanner',
      },
    });

    if (!userRes.ok) {
      return res.status(userRes.status).json({
        error: 'Failed to retrieve GitHub user profile with access token.',
      });
    }

    const userData = await userRes.json();

    // 3. Establish server-side session and set httpOnly cookie
    const session = createSession(userData, accessToken);
    const isProduction = config.nodeEnv === 'production';
    res.setHeader('Set-Cookie', buildSessionCookie(session.sessionId, isProduction));

    // 4. Redirect to frontend ingest page with connected=github parameter
    const frontendBase = (config.frontendUrl || 'http://localhost:5173').replace(/\/+$/, '');
    const targetUrl = `${frontendBase}/ingest?connected=github`;
    return res.redirect(targetUrl);
  } catch (err) {
    console.error('Unhandled GitHub OAuth callback error:', err);
    return res.status(500).json({
      error: 'Internal server error while completing GitHub authentication.',
    });
  }
});

/**
 * @route   GET /api/auth/me
 * @desc    Returns the authenticated GitHub user profile, or 401 if unauthenticated
 * @access  Private
 */
router.get('/api/auth/me', (req, res) => {
  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({
      error: 'Unauthorized. No active GitHub session found.',
    });
  }

  return res.status(200).json({
    authenticated: true,
    user: sanitizeUser(session.user),
  });
});

/**
 * @route   POST /api/auth/logout
 * @desc    Terminates the active session and clears the session cookie
 * @access  Public
 */
router.post('/api/auth/logout', (req, res) => {
  const sessionId = extractSessionId(req);
  if (sessionId) {
    destroySession(sessionId);
  }

  res.setHeader('Set-Cookie', buildClearCookie());
  return res.status(200).json({
    success: true,
    message: 'Logged out successfully.',
  });
});

export default router;
