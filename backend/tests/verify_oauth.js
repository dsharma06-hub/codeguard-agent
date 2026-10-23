import assert from 'assert';
import http from 'http';
import app from '../src/app.js';
import { config } from '../src/config/env.js';
import {
  createSession,
  destroySession,
  getSession,
  clearAllAuthData,
  SESSION_COOKIE_NAME,
} from '../src/services/authService.js';

async function runOAuthVerification() {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const BACKEND_URL = `http://127.0.0.1:${port}`;

  console.log('====================================================');
  console.log(' CodeGuard GitHub OAuth & Session Verification     ');
  console.log(' Target Backend URL:', BACKEND_URL);
  console.log('====================================================\n');

  // Test 1: Unauthenticated /api/auth/me returns 401
  console.log('Test 1: Unauthenticated GET /api/auth/me returns 401...');
  const meRes = await fetch(`${BACKEND_URL}/api/auth/me`);
  assert.strictEqual(meRes.status, 401, `Expected 401, got ${meRes.status}`);
  const meData = await meRes.json();
  assert.ok(meData.error && meData.error.includes('Unauthorized'), 'Error message should indicate unauthorized');
  console.log('  ✓ Returns 401 Unauthorized when no session cookie is provided');

  // Test 2: Unauthenticated GET /api/github/repos returns 401
  console.log('\nTest 2: Unauthenticated GET /api/github/repos returns 401...');
  const reposRes = await fetch(`${BACKEND_URL}/api/github/repos`);
  assert.strictEqual(reposRes.status, 401, `Expected 401, got ${reposRes.status}`);
  const reposData = await reposRes.json();
  assert.ok(reposData.error && reposData.error.includes('Unauthorized'), 'Error message should indicate unauthorized');
  console.log('  ✓ Returns 401 Unauthorized when attempting to browse repositories without session');

  // Test 3: GET /api/auth/github redirect URL is correctly formed
  console.log('\nTest 3: Validating GET /api/auth/github authorize redirect URL...');
  const authRes = await fetch(`${BACKEND_URL}/api/auth/github`, {
    redirect: 'manual', // Don't follow redirect to GitHub
  });
  assert.strictEqual(authRes.status, 302, `Expected 302 Found redirect, got ${authRes.status}`);

  const redirectLocation = authRes.headers.get('location');
  assert.ok(redirectLocation, 'Response must include Location header');
  assert.ok(redirectLocation.startsWith('https://github.com/login/oauth/authorize?'), 'Must redirect to GitHub authorize URL');

  const redirectUrl = new URL(redirectLocation);
  assert.strictEqual(redirectUrl.searchParams.get('client_id'), config.githubClientId, 'client_id must match GITHUB_CLIENT_ID from .env');
  assert.strictEqual(redirectUrl.searchParams.get('redirect_uri'), config.githubRedirectUri, 'redirect_uri must match configured callback');
  assert.ok(redirectUrl.searchParams.get('scope').includes('repo'), 'scope must include "repo" to access private repositories');

  const stateParam = redirectUrl.searchParams.get('state');
  assert.ok(stateParam && stateParam.length >= 32, 'state parameter must be a secure random CSRF token');
  console.log(`  ✓ 302 Redirect correctly formed:`);
  console.log(`    - client_id: ${redirectUrl.searchParams.get('client_id')}`);
  console.log(`    - redirect_uri: ${redirectUrl.searchParams.get('redirect_uri')}`);
  console.log(`    - scope: ${redirectUrl.searchParams.get('scope')}`);
  console.log(`    - state: ${stateParam.slice(0, 12)}... (CSRF token)`);

  // Test 4: CSRF State validation on callback
  console.log('\nTest 4: Validating CSRF protection on callback...');
  const invalidStateRes = await fetch(`${BACKEND_URL}/api/auth/github/callback?code=mock_code&state=invalid_forged_state`);
  assert.strictEqual(invalidStateRes.status, 400, `Expected 400 Bad Request for invalid state, got ${invalidStateRes.status}`);
  const invalidStateData = await invalidStateRes.json();
  assert.ok(invalidStateData.error.includes('CSRF'), 'Error message should explicitly mention CSRF validation failure');
  console.log('  ✓ Invalid / forged state token rejected with 400 Bad Request');

  const missingStateRes = await fetch(`${BACKEND_URL}/api/auth/github/callback?code=mock_code`);
  assert.strictEqual(missingStateRes.status, 400, 'Expected 400 Bad Request for missing state');
  console.log('  ✓ Missing state parameter rejected with 400 Bad Request');

  // Test 5: In-memory session lifecycle and token privacy
  console.log('\nTest 5: Testing session lifecycle, cookie authentication, and token privacy...');
  const mockUser = {
    id: 998877,
    login: 'test-developer',
    name: 'Test Developer',
    avatar_url: 'https://avatars.githubusercontent.com/u/998877?v=4',
    email: 'developer@example.com',
  };
  const mockToken = 'gho_secretMockAccessTokenThatMustNeverLeak1234567890';

  const testSession = createSession(mockUser, mockToken);
  assert.ok(testSession.sessionId, 'Session should have unique sessionId');
  assert.strictEqual(getSession(testSession.sessionId)?.accessToken, mockToken, 'Session stores accessToken server-side');

  // Call /api/auth/me with session cookie
  const authMeRes = await fetch(`${BACKEND_URL}/api/auth/me`, {
    headers: {
      Cookie: `${SESSION_COOKIE_NAME}=${testSession.sessionId}`,
    },
  });
  assert.strictEqual(authMeRes.status, 200, `Expected 200 OK, got ${authMeRes.status}`);
  const authMeData = await authMeRes.json();

  assert.strictEqual(authMeData.authenticated, true, 'Response should report authenticated: true');
  assert.strictEqual(authMeData.user.username, mockUser.login, 'Username must match logged-in user');
  assert.strictEqual(authMeData.user.avatarUrl, mockUser.avatar_url, 'Avatar URL must match');

  // Security test: ensure accessToken is NEVER returned in API responses
  const rawResponseString = JSON.stringify(authMeData);
  assert.ok(!rawResponseString.includes(mockToken), 'CRITICAL: Raw access token must NEVER be returned in user profile response!');
  assert.strictEqual(authMeData.user.accessToken, undefined, 'accessToken property must be undefined in public user payload');
  console.log('  ✓ Authenticated user profile returned successfully');
  console.log('  ✓ Verified: Access token is never leaked in API response');

  // Test 6: Logout endpoint clears session and cookie
  console.log('\nTest 6: Testing POST /api/auth/logout...');
  const logoutRes = await fetch(`${BACKEND_URL}/api/auth/logout`, {
    method: 'POST',
    headers: {
      Cookie: `${SESSION_COOKIE_NAME}=${testSession.sessionId}`,
    },
  });
  assert.strictEqual(logoutRes.status, 200, `Expected 200 OK, got ${logoutRes.status}`);

  const setCookieHeader = logoutRes.headers.get('set-cookie') || '';
  assert.ok(setCookieHeader.includes('Max-Age=0'), 'Set-Cookie header should expire cookie immediately (Max-Age=0)');
  assert.ok(setCookieHeader.includes('HttpOnly'), 'Set-Cookie header should retain HttpOnly flag');

  // Confirm session is destroyed from in-memory store
  assert.strictEqual(getSession(testSession.sessionId), null, 'Session should be removed from sessionStore after logout');

  // Subsequent request with old cookie must fail with 401
  const postLogoutMe = await fetch(`${BACKEND_URL}/api/auth/me`, {
    headers: {
      Cookie: `${SESSION_COOKIE_NAME}=${testSession.sessionId}`,
    },
  });
  assert.strictEqual(postLogoutMe.status, 401, 'Request after logout must return 401 Unauthorized');
  console.log('  ✓ Logout clears in-memory session and sends expiring Set-Cookie header');

  // Clean up test data
  clearAllAuthData();

  console.log('\n====================================================');
  console.log(' ALL OAUTH & SESSION TESTS PASSED!                  ');
  console.log('====================================================\n');
  console.log('----------------------------------------------------');
  console.log(' MANUAL TESTING INSTRUCTIONS (Real Browser Login):   ');
  console.log('----------------------------------------------------');
  const serverBase = `http://localhost:${config.port || 5000}`;
  console.log('1. Open your web browser.');
  console.log(`2. Navigate to: ${serverBase}/api/auth/github`);
  console.log('3. Authorize the CodeGuard OAuth application on GitHub.');
  console.log('4. GitHub will redirect back to http://localhost:5000/api/auth/github/callback,');
  console.log('   which sets an httpOnly session cookie (codeguard_session) and redirects to frontend.');
  console.log(`5. Verify your session by visiting: ${serverBase}/api/auth/me`);
  console.log(`6. Browse your repositories at: ${serverBase}/api/github/repos`);
  console.log(`7. Log out by issuing a POST request to: ${serverBase}/api/auth/logout`);
  console.log('----------------------------------------------------\n');

  server.close();
}

runOAuthVerification().catch((err) => {
  console.error('\n❌ OAuth verification failed:', err);
  process.exit(1);
});
