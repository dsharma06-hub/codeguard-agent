import assert from 'assert';
import AdmZip from 'adm-zip';
import os from 'os';
import path from 'path';
import fs from 'fs';

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';

async function uploadZip(zip) {
  const zipBuffer = zip.toBuffer();
  const form = new FormData();
  const blob = new Blob([zipBuffer], { type: 'application/zip' });
  form.append('file', blob, 'test_repo.zip');

  const res = await fetch(`${BACKEND_URL}/api/scan/upload`, {
    method: 'POST',
    body: form,
  });

  if (res.status !== 200) {
    const errText = await res.text();
    console.error(`Upload failed (${res.status}):`, errText);
  }
  assert.strictEqual(res.status, 200, `Expected 200 OK, got ${res.status}`);
  return await res.json();
}

async function runVerification() {
  console.log('====================================================');
  console.log(' CodeGuard AI Antipatterns Detector Verification   ');
  console.log(' Target Backend URL:', BACKEND_URL);
  console.log('====================================================\n');

  // Test 1: Repo with sensitive routes and NO rate limiting (should flag)
  console.log('Test 1: Sensitive routes with NO rate limiting in repo (should flag)...');
  const zipNoRateLimit = new AdmZip();
  zipNoRateLimit.addFile(
    'src/routes/auth.js',
    Buffer.from(`
const express = require('express');
const router = express.Router();

router.post('/login', (req, res) => {
    res.json({ token: 'jwt-token' });
});

router.post('/register', (req, res) => {
    const { username, email } = req.body;
    res.json({ id: 1 });
});

module.exports = router;
`)
  );
  zipNoRateLimit.addFile(
    'src/app.js',
    Buffer.from(`
const express = require('express');
const authRoutes = require('./routes/auth');
const app = express();
app.use(express.json());
app.use('/auth', authRoutes);
module.exports = app;
`)
  );

  const res1 = await uploadZip(zipNoRateLimit);
  assert.strictEqual(res1.findings.length, 2, `Expected 2 findings, got ${res1.findings.length}`);
  for (const finding of res1.findings) {
    assert.strictEqual(finding.category, 'ai-antipattern', `Expected category 'ai-antipattern', got ${finding.category}`);
    assert.strictEqual(finding.severity, 'medium', `Expected severity 'medium', got ${finding.severity}`);
    assert.strictEqual(finding.cwe, 'CWE-307', `Expected CWE-307, got ${finding.cwe}`);
    assert.ok(finding.title.includes('Missing Rate Limiting'), 'Title should describe missing rate limiting');
  }
  console.log(`  ✓ Flagged ${res1.findings.length} sensitive routes with MEDIUM severity, CWE-307, category 'ai-antipattern'`);

  // Test 2: The SAME repo WITH rate limiting present (should NOT flag)
  console.log('\nTest 2: Same repo WITH rate limiting present in repo (should NOT flag)...');
  const zipWithRateLimit = new AdmZip();
  zipWithRateLimit.addFile(
    'src/routes/auth.js',
    Buffer.from(`
const express = require('express');
const router = express.Router();

router.post('/login', (req, res) => {
    res.json({ token: 'jwt-token' });
});

router.post('/register', (req, res) => {
    const { username, email } = req.body;
    res.json({ id: 1 });
});

module.exports = router;
`)
  );
  zipWithRateLimit.addFile(
    'src/app.js',
    Buffer.from(`
const express = require('express');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/auth');

const app = express();
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

app.use(express.json());
app.use('/auth', authRoutes);
module.exports = app;
`)
  );

  const res2 = await uploadZip(zipWithRateLimit);
  assert.strictEqual(res2.findings.length, 0, `Expected 0 findings when rate limiter is present, got ${res2.findings.length}`);
  console.log('  ✓ 0 findings: All missing rate-limiting findings successfully suppressed by repo-level guard');

  // Test 3: Repo with hardcoded production URLs in HTTP client calls (should flag)
  console.log('\nTest 3: Hardcoded production endpoints in fetch/axios (should flag)...');
  const zipHardcodedEndpoints = new AdmZip();
  zipHardcodedEndpoints.addFile(
    'src/services/billing.ts',
    Buffer.from(`
import axios from 'axios';

export async function fetchUserData() {
    const res = await fetch("https://api.mycompany.com/v1/users");
    return res.json();
}

export async function processPayment(paymentDetails: any) {
    const res = await axios.post("https://production.codeguard.io/api/checkout", paymentDetails);
    return res.data;
}
`)
  );

  const res3 = await uploadZip(zipHardcodedEndpoints);
  assert.strictEqual(res3.findings.length, 2, `Expected 2 findings, got ${res3.findings.length}`);
  for (const finding of res3.findings) {
    assert.strictEqual(finding.category, 'ai-antipattern', `Expected category 'ai-antipattern', got ${finding.category}`);
    assert.strictEqual(finding.severity, 'low', `Expected severity 'low', got ${finding.severity}`);
    assert.strictEqual(finding.cwe, 'CWE-1188', `Expected CWE-1188, got ${finding.cwe}`);
    assert.ok(finding.title.includes('Hardcoded Production Endpoint URL'), 'Title should describe hardcoded endpoint');
  }
  console.log(`  ✓ Flagged ${res3.findings.length} hardcoded production URLs with LOW severity, CWE-1188, category 'ai-antipattern'`);

  // Test 4: Repo using environment-based configuration correctly (should NOT flag)
  console.log('\nTest 4: Correct environment-based configuration & safe URLs (should NOT flag)...');
  const zipSafeEndpoints = new AdmZip();
  zipSafeEndpoints.addFile(
    'src/services/billing.ts',
    Buffer.from(`
import axios from 'axios';

export async function fetchUserData() {
    // Correct env-based configuration
    const res = await fetch(process.env.API_BASE_URL + "/v1/users");
    return res.json();
}

export async function checkLocalDev() {
    // Localhost dev/test URLs are allowed
    return await fetch("http://localhost:3000/health");
}

export async function checkThirdParty() {
    // Fixed public third-party APIs are allowed
    return await axios.get("https://api.github.com/repos/expressjs/cors");
}
`)
  );

  const res4 = await uploadZip(zipSafeEndpoints);
  assert.strictEqual(res4.findings.length, 0, `Expected 0 findings for safe URLs and env vars, got ${res4.findings.length}`);
  console.log('  ✓ 0 findings: Environment variables, localhost, and third-party APIs correctly passed without false positives');

  // Test 5: Temporary storage cleanup check
  console.log('\nTest 5: Temporary directory cleanup verification...');
  const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
  if (fs.existsSync(tempBaseDir)) {
    const remaining = fs.readdirSync(tempBaseDir);
    assert.strictEqual(remaining.length, 0, `Expected 0 lingering scan directories, found ${remaining.length}`);
  }
  console.log('  ✓ 0 lingering directories in %TEMP%\\codeguard-scans');

  console.log('\n====================================================');
  console.log(' ALL AI ANTIPATTERNS VERIFICATION TESTS PASSED!     ');
  console.log('====================================================\n');
}

runVerification().catch((err) => {
  console.error('\n❌ Verification failed:', err);
  process.exit(1);
});
