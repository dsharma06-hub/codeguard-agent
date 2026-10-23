import crypto from 'crypto';

export const SESSION_COOKIE_NAME = 'codeguard_session';
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const OAUTH_STATE_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes

/**
 * In-memory stores for sessions and OAuth state tokens
 */
const sessionStore = new Map();
const oauthStateStore = new Map();

/**
 * Parses raw Cookie header string into key-value pairs
 * @param {string} [cookieHeader='']
 * @returns {Record<string, string>}
 */
export function parseCookies(cookieHeader = '') {
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return cookies;

  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const equalIdx = part.indexOf('=');
    if (equalIdx < 0) continue;
    const key = part.slice(0, equalIdx).trim();
    const val = part.slice(equalIdx + 1).trim();
    if (!key) continue;
    try {
      cookies[key] = decodeURIComponent(val);
    } catch {
      cookies[key] = val;
    }
  }
  return cookies;
}

/**
 * Creates and stores a cryptographically secure random state parameter for OAuth CSRF protection
 * @param {string} [returnTo]
 * @returns {string}
 */
export function createOAuthState(returnTo = '') {
  // Purge expired states
  const now = Date.now();
  for (const [key, val] of oauthStateStore.entries()) {
    if (now > val.expiresAt) {
      oauthStateStore.delete(key);
    }
  }

  const state = crypto.randomBytes(24).toString('hex');
  oauthStateStore.set(state, {
    state,
    returnTo,
    createdAt: now,
    expiresAt: now + OAUTH_STATE_MAX_AGE_MS,
  });
  return state;
}

/**
 * Validates and consumes an OAuth state parameter (one-time use)
 * @param {string} state
 * @returns {boolean}
 */
export function validateOAuthState(state) {
  if (!state || typeof state !== 'string') return false;

  const record = oauthStateStore.get(state);
  if (!record) return false;

  // Single-use token: remove immediately
  oauthStateStore.delete(state);

  if (Date.now() > record.expiresAt) {
    return false;
  }
  return true;
}

/**
 * Creates a new authenticated user session
 * @param {object} userData - GitHub user profile
 * @param {string} accessToken - GitHub OAuth personal access token
 * @returns {object} Session record with sessionId
 */
export function createSession(userData, accessToken) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const now = Date.now();

  const session = {
    sessionId,
    user: {
      id: userData.id,
      login: userData.login,
      name: userData.name || userData.login,
      avatar_url: userData.avatar_url || '',
      email: userData.email || '',
    },
    accessToken,
    createdAt: now,
    expiresAt: now + SESSION_MAX_AGE_MS,
  };

  sessionStore.set(sessionId, session);
  return session;
}

/**
 * Retrieves an active session by its sessionId, returning null if invalid or expired
 * @param {string} sessionId
 * @returns {object|null}
 */
export function getSession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') return null;

  const session = sessionStore.get(sessionId);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    sessionStore.delete(sessionId);
    return null;
  }

  return session;
}

/**
 * Destroys an active session
 * @param {string} sessionId
 * @returns {boolean}
 */
export function destroySession(sessionId) {
  if (!sessionId) return false;
  return sessionStore.delete(sessionId);
}

/**
 * Extracts sessionId from request cookies or Bearer Authorization header
 * @param {object} req - Express request
 * @returns {string|null}
 */
export function extractSessionId(req) {
  if (!req) return null;

  // 1. From httpOnly cookie
  const cookies = parseCookies(req.headers?.cookie);
  if (cookies[SESSION_COOKIE_NAME]) {
    return cookies[SESSION_COOKIE_NAME];
  }

  // 2. Fallback: Authorization header (Bearer <sessionId>) for programmatic API calls
  const authHeader = req.headers?.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }

  return null;
}

/**
 * Resolves the authenticated session from an Express request
 * @param {object} req - Express request
 * @returns {object|null}
 */
export function getSessionFromRequest(req) {
  const sessionId = extractSessionId(req);
  if (!sessionId) return null;
  return getSession(sessionId);
}

/**
 * Returns a sanitized public user object, guaranteeing no access tokens are exposed
 * @param {object} user
 * @returns {object}
 */
export function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.login,
    name: user.name || user.login,
    avatarUrl: user.avatar_url,
  };
}

/**
 * Helper to build Set-Cookie header for session cookie
 * @param {string} sessionId
 * @param {boolean} [isSecure=false]
 * @returns {string}
 */
export function buildSessionCookie(sessionId, isSecure = false) {
  const maxAgeSecs = Math.floor(SESSION_MAX_AGE_MS / 1000);
  const secureFlag = isSecure ? '; Secure' : '';
  return `${SESSION_COOKIE_NAME}=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSecs}${secureFlag}`;
}

/**
 * Helper to build Set-Cookie header to clear session cookie
 * @returns {string}
 */
export function buildClearCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

/**
 * Clear all stores (useful for test resets)
 */
export function clearAllAuthData() {
  sessionStore.clear();
  oauthStateStore.clear();
}
