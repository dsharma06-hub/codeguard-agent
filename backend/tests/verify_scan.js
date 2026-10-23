import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import AdmZip from 'adm-zip';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BASE_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';
const FIXTURE_ZIP_PATH = path.join(__dirname, 'fixtures', 'sample-vulnerable-repo.zip');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  ✓ ${message}`);
  } else {
    failedTests++;
    console.error(`  ✗ FAIL: ${message}`);
  }
}

async function runVerification() {
  console.log('====================================================');
  console.log(' CodeGuard Backend Scan Orchestration Verification');
  console.log(' Target Backend URL:', BASE_URL);
  console.log('====================================================\n');

  // Test 1: Service connectivity & health
  console.log('Test Suite 1: Connectivity & System Status');
  try {
    const statusRes = await fetch(`${BASE_URL}/api/status`);
    assert(statusRes.status === 200, 'GET /api/status responds with 200 OK');
    const statusData = await statusRes.json();
    assert(statusData.backend === 'ok', 'Backend reports status: ok');
    assert(statusData.analysisService === 'ok', 'Analysis Service reports status: ok');
  } catch (err) {
    assert(false, `Connectivity check failed: ${err.message}`);
    console.error('Cannot proceed if backend is not reachable.');
    process.exit(1);
  }

  // Test 2: POST /api/scan/repo endpoint is active and validates input
  console.log('\nTest Suite 2: Repo URL Scanning Route Validation');
  try {
    const repoRes = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert(repoRes.status === 400, 'POST /api/scan/repo rejects empty payload with 400 Bad Request');
    const repoData = await repoRes.json();
    assert(
      typeof repoData.error === 'string' && repoData.error.includes('repoUrl'),
      '400 payload includes clear descriptive message'
    );
  } catch (err) {
    assert(false, `POST /api/scan/repo error: ${err.message}`);
  }

  // Test 3: Upload with no file provided
  console.log('\nTest Suite 3: Missing File Validation');
  try {
    const noFileFormData = new FormData();
    const noFileRes = await fetch(`${BASE_URL}/api/scan/upload`, {
      method: 'POST',
      body: noFileFormData,
    });
    assert(noFileRes.status === 400, 'POST /api/scan/upload with no file returns 400 Bad Request');
    const noFileData = await noFileRes.json();
    assert(typeof noFileData.error === 'string', '400 payload includes error message');
  } catch (err) {
    assert(false, `Missing file test error: ${err.message}`);
  }

  // Test 4: Upload corrupted / invalid zip
  console.log('\nTest Suite 4: Corrupted Zip Handling');
  try {
    const corruptFormData = new FormData();
    const corruptBlob = new Blob(['Not a real zip archive header content here'], {
      type: 'application/zip',
    });
    corruptFormData.append('file', corruptBlob, 'broken.zip');

    const corruptRes = await fetch(`${BASE_URL}/api/scan/upload`, {
      method: 'POST',
      body: corruptFormData,
    });
    assert(corruptRes.status === 400, 'POST /api/scan/upload with corrupted zip returns 400');
    const corruptData = await corruptRes.json();
    assert(
      corruptData.error.toLowerCase().includes('corrupted') || corruptData.error.toLowerCase().includes('invalid'),
      '400 error indicates corrupted or invalid zip archive'
    );
  } catch (err) {
    assert(false, `Corrupt zip test error: ${err.message}`);
  }

  // Test 4b: Zip-Slip / Path Traversal Attack Prevention
  console.log('\nTest Suite 4b: Zip-Slip / Path Traversal Attack Prevention');
  try {
    const maliciousPaths = [
      '../../../etc/passwd',
      '..\\..\\Windows\\System32\\evil.dll',
      'subfolder/../../escaped.js',
    ];

    for (const malPath of maliciousPaths) {
      const maliciousZip = new AdmZip();
      maliciousZip.addFile('payload.txt', Buffer.from('malicious payload content', 'utf8'));
      maliciousZip.getEntries()[0].entryName = malPath;
      const malBuffer = maliciousZip.toBuffer();

      const malFormData = new FormData();
      const malBlob = new Blob([malBuffer], { type: 'application/zip' });
      malFormData.append('file', malBlob, 'malicious.zip');

      const malRes = await fetch(`${BASE_URL}/api/scan/upload`, {
        method: 'POST',
        body: malFormData,
      });

      assert(
        malRes.status === 400,
        `Zip-slip entry '${malPath}' rejected with HTTP 400 Bad Request`
      );
      const malData = await malRes.json();
      assert(
        malData.error && malData.error.toLowerCase().includes('zip slip'),
        `Error response explicitly identifies zip slip / path traversal: "${malData.error}"`
      );
    }
  } catch (err) {
    assert(false, `Zip slip test error: ${err.message}`);
  }

  // Test 5: Upload zip with no code files (e.g. only README.md)
  console.log('\nTest Suite 5: Archive with No Target Source Files');
  try {
    const emptyZip = new AdmZip();
    emptyZip.addFile('README.md', Buffer.from('# Documentation only repo\nNo source code here.', 'utf8'));
    emptyZip.addFile('docs/guide.txt', Buffer.from('Just text documentation.', 'utf8'));
    const emptyBuffer = emptyZip.toBuffer();

    const emptyFormData = new FormData();
    const emptyBlob = new Blob([emptyBuffer], { type: 'application/zip' });
    emptyFormData.append('file', emptyBlob, 'docs-only.zip');

    const emptyRes = await fetch(`${BASE_URL}/api/scan/upload`, {
      method: 'POST',
      body: emptyFormData,
    });
    assert(emptyRes.status === 200, 'POST /api/scan/upload with docs-only zip returns 200 OK');
    const emptyData = await emptyRes.json();
    assert(emptyData.findings.length === 0, 'Returns 0 findings');
    assert(emptyData.summary.total === 0, 'Summary total is 0');
    assert(emptyData.metadata.filesScanned === 0, 'Files scanned is 0');
  } catch (err) {
    assert(false, `Docs-only zip test error: ${err.message}`);
  }

  // Test 6: Full Vulnerable Repo Scan with All 3 Detectors
  console.log('\nTest Suite 6: Full Scan with Hardcoded Secret, SQLi & Vulnerable Dependency');
  try {
    if (!fs.existsSync(FIXTURE_ZIP_PATH)) {
      throw new Error(`Fixture file not found: ${FIXTURE_ZIP_PATH}`);
    }

    const zipBuffer = fs.readFileSync(FIXTURE_ZIP_PATH);
    const formData = new FormData();
    const fileBlob = new Blob([zipBuffer], { type: 'application/zip' });
    formData.append('file', fileBlob, 'sample-vulnerable-repo.zip');

    const scanStartTime = Date.now();
    const scanRes = await fetch(`${BASE_URL}/api/scan/upload`, {
      method: 'POST',
      body: formData,
    });
    const scanDuration = Date.now() - scanStartTime;

    assert(scanRes.status === 200, `POST /api/scan/upload returns 200 OK (${scanDuration}ms)`);
    const scanData = await scanRes.json();

    // Verify Metadata
    assert(scanData.metadata !== undefined, 'Response includes metadata object');
    assert(scanData.metadata.repoName === 'sample-vulnerable-repo', 'Metadata repoName matches archive name');
    assert(typeof scanData.metadata.branch === 'string', 'Metadata branch is defined');
    assert(typeof scanData.metadata.commitHash === 'string', 'Metadata commitHash is defined');
    assert(typeof scanData.metadata.scanTimestamp === 'string', 'Metadata scanTimestamp is valid string');
    assert(typeof scanData.metadata.durationMs === 'number' && scanData.metadata.durationMs >= 0, 'Metadata durationMs is numeric');
    assert(scanData.metadata.filesScanned === 4, `Metadata filesScanned matches discovered target files (found: ${scanData.metadata.filesScanned}, expected: 4)`);
    assert(scanData.metadata.linesAnalyzed > 0, `Metadata linesAnalyzed is positive (${scanData.metadata.linesAnalyzed} lines)`);

    // Verify Summary
    assert(scanData.summary !== undefined, 'Response includes summary object');
    assert(scanData.summary.total >= 3, `Summary total >= 3 findings (found ${scanData.summary.total})`);
    const sumSeverities =
      scanData.summary.critical +
      scanData.summary.high +
      scanData.summary.medium +
      scanData.summary.low;
    assert(sumSeverities === scanData.summary.total, 'Severity breakdown sums exactly to total findings count');

    // Verify Findings Array & Categories
    const findings = scanData.findings || [];
    assert(Array.isArray(findings) && findings.length >= 3, `Findings array has >= 3 items (found ${findings.length})`);

    const categoriesFound = new Set(findings.map((f) => f.category));
    assert(categoriesFound.has('secret'), "Findings contain category 'secret'");
    assert(categoriesFound.has('injection'), "Findings contain category 'injection'");
    assert(categoriesFound.has('dependency'), "Findings contain category 'dependency'");

    // Check lowercase severity enforcement across all findings
    const validSeverities = new Set(['critical', 'high', 'medium', 'low', 'info']);
    const allSeveritiesValid = findings.every((f) => validSeverities.has(f.severity));
    assert(allSeveritiesValid, 'All finding severities conform to lowercase union');

    // Inspect individual detectors
    const secretFinding = findings.find((f) => f.category === 'secret');
    if (secretFinding) {
      assert(secretFinding.filePath === 'src/config.ts', 'Secret finding filePath is src/config.ts');
      assert(secretFinding.cwe === 'CWE-798', 'Secret finding CWE is CWE-798');
      assert(secretFinding.codeSnippet !== undefined, 'Secret finding has codeSnippet');
      assert(secretFinding.codeSnippet.language === 'typescript', 'Secret snippet language is typescript');
      assert(
        secretFinding.codeSnippet.lines.some((l) => l.includes('AKIAIOSFODNN7EXAMPLE')),
        'Secret code snippet contains the sensitive key line'
      );
      assert(secretFinding.codeSnippet.highlightLines.length > 0, 'Secret snippet highlightLines is populated');
    } else {
      assert(false, 'Expected secret finding not found in array');
    }

    const sqliFinding = findings.find((f) => f.category === 'injection');
    if (sqliFinding) {
      assert(sqliFinding.filePath === 'src/db.ts', 'SQLi finding filePath is src/db.ts');
      assert(sqliFinding.cwe === 'CWE-89', 'SQLi finding CWE is CWE-89');
      assert(sqliFinding.codeSnippet.language === 'typescript', 'SQLi snippet language is typescript');
      assert(
        sqliFinding.codeSnippet.lines.some((l) => l.includes('SELECT * FROM users')),
        'SQLi code snippet contains the query line'
      );
    } else {
      assert(false, 'Expected SQL injection finding not found in array');
    }

    const depFinding = findings.find((f) => f.category === 'dependency');
    if (depFinding) {
      assert(depFinding.filePath === 'package.json', 'Dependency finding filePath is package.json');
      assert(typeof depFinding.cwe === 'string', `Dependency finding CWE is populated (${depFinding.cwe})`);
      assert(depFinding.codeSnippet.language === 'json', 'Dependency snippet language is json');
      assert(
        depFinding.codeSnippet.lines.some((l) => l.includes('lodash')),
        'Dependency code snippet contains vulnerable package entry'
      );
    } else {
      assert(false, 'Expected vulnerable dependency finding not found in array');
    }
  } catch (err) {
    assert(false, `Full scan test error: ${err.message}`);
  }

  // Test 7: Verify Temp Directory Cleanup
  console.log('\nTest Suite 7: Temporary Extraction Folder Cleanup Verification');
  try {
    const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
    let remainingFolders = 0;
    if (fs.existsSync(tempBaseDir)) {
      const items = fs.readdirSync(tempBaseDir);
      remainingFolders = items.length;
    }
    assert(
      remainingFolders === 0,
      `No leftover temporary scan directories in os.tmpdir()/codeguard-scans (found ${remainingFolders})`
    );
  } catch (err) {
    assert(false, `Temp directory cleanup verification error: ${err.message}`);
  }

  // Test 8: Consecutive Multi-Run Cleanup Verification (3x Repeated Scans)
  console.log('\nTest Suite 8: Consecutive Multi-Run Cleanup Verification (3x Repeated Scans)');
  try {
    const zipBuffer = fs.readFileSync(FIXTURE_ZIP_PATH);
    const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
    for (let run = 1; run <= 3; run++) {
      const formData = new FormData();
      const fileBlob = new Blob([zipBuffer], { type: 'application/zip' });
      formData.append('file', fileBlob, 'sample-vulnerable-repo.zip');

      const res = await fetch(`${BASE_URL}/api/scan/upload`, {
        method: 'POST',
        body: formData,
      });
      assert(res.status === 200, `Upload scan run ${run}/3 completed with 200 OK`);
      let count = 0;
      if (fs.existsSync(tempBaseDir)) {
        count = fs.readdirSync(tempBaseDir).length;
      }
      assert(
        count === 0,
        `Post-scan run ${run}/3 has 0 lingering scan directories (found: ${count})`
      );
    }
  } catch (err) {
    assert(false, `Consecutive scan cleanup verification error: ${err.message}`);
  }

  console.log('\n====================================================');
  console.log(` Verification Summary: ${passedTests}/${totalTests} Passed (${failedTests} Failed)`);
  console.log('====================================================');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runVerification().catch((err) => {
  console.error('Unhandled verification error:', err);
  process.exit(1);
});
