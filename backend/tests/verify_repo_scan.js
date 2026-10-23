import fs from 'fs';
import path from 'path';
import os from 'os';

const BASE_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';
const TARGET_REPO = 'expressjs/cors';

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

async function runRepoScanVerification() {
  console.log('====================================================');
  console.log(' CodeGuard Remote GitHub Repository Scan Verification');
  console.log(' Target Backend URL:', BASE_URL);
  console.log(' Target Public Repo:', TARGET_REPO);
  console.log('====================================================\n');

  // Test Suite 1: Service Connectivity
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

  // Test Suite 2: Invalid URL & Malformed Inputs (HTTP 400)
  console.log('\nTest Suite 2: Input Validation Error Paths (HTTP 400)');
  try {
    // 2a: Missing repoUrl
    const resNoBody = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert(resNoBody.status === 400, 'Missing repoUrl field returns 400 Bad Request');
    const dataNoBody = await resNoBody.json();
    assert(typeof dataNoBody.error === 'string', '400 response includes error description');

    // 2b: Empty string repoUrl
    const resEmpty = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: '   ' }),
    });
    assert(resEmpty.status === 400, 'Empty repoUrl returns 400 Bad Request');

    // 2c: Non-GitHub domain
    const resNonGithub = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: 'https://gitlab.com/expressjs/cors' }),
    });
    assert(resNonGithub.status === 400, 'Non-GitHub URL (e.g. GitLab) returns 400 Bad Request');
    const dataNonGithub = await resNonGithub.json();
    assert(
      dataNonGithub.error.toLowerCase().includes('github.com'),
      '400 error specifies only github.com is supported'
    );

    // 2d: Command flag / shell metacharacters injection attempt
    const resFlagInjection = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: '--upload-pack=evil' }),
    });
    assert(resFlagInjection.status === 400, 'Leading flag argument returns 400 Bad Request');

    const resShellInjection = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: 'expressjs/cors; rm -rf /' }),
    });
    assert(resShellInjection.status === 400, 'Shell metacharacters in slug return 400 Bad Request');

    // 2e: Malformed slug without slash
    const resNoSlash = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: 'justareponame' }),
    });
    assert(resNoSlash.status === 400, 'Single-identifier slug without owner returns 400 Bad Request');
  } catch (err) {
    assert(false, `Input validation test failed: ${err.message}`);
  }

  // Test Suite 3: Non-existent / Private Repository (HTTP 404)
  console.log('\nTest Suite 3: Non-Existent Repository Error Path (HTTP 404)');
  try {
    const nonexistentRepo = 'doesnotexist-org-98765/doesnotexist-repo-43210';
    const start404 = Date.now();
    const res404 = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: nonexistentRepo }),
    });
    const duration404 = Date.now() - start404;

    assert(res404.status === 404, 'Non-existent repository returns 404 Not Found');
    assert(duration404 < 15000, `Non-existent repo fails fast without hanging (${duration404}ms < 15000ms)`);
    const data404 = await res404.json();
    assert(
      typeof data404.error === 'string' && data404.error.toLowerCase().includes('not found'),
      '404 payload contains clear "not found" message'
    );
  } catch (err) {
    assert(false, `Non-existent repo test failed: ${err.message}`);
  }

  // Test Suite 4: Happy Path - Real Public GitHub Repository Shallow Clone & Scan
  console.log(`\nTest Suite 4: Real Public GitHub Scan (${TARGET_REPO})`);
  let scanResult;
  try {
    const startScan = Date.now();
    const resScan = await fetch(`${BASE_URL}/api/scan/repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: TARGET_REPO }),
    });
    const scanLatency = Date.now() - startScan;

    assert(resScan.status === 200, `POST /api/scan/repo returns 200 OK (in ${scanLatency}ms)`);
    scanResult = await resScan.json();

    // 4a: Validate Metadata
    assert(scanResult.metadata !== undefined, 'Response includes metadata object');
    assert(scanResult.metadata.repoName === TARGET_REPO, `metadata.repoName matches '${TARGET_REPO}'`);
    assert(typeof scanResult.metadata.branch === 'string' && scanResult.metadata.branch.length > 0, `metadata.branch is present ('${scanResult.metadata?.branch}')`);
    assert(typeof scanResult.metadata.commitHash === 'string' && scanResult.metadata.commitHash.length > 0, `metadata.commitHash is present ('${scanResult.metadata?.commitHash}')`);
    assert(scanResult.metadata.filesScanned > 0, `metadata.filesScanned is positive (${scanResult.metadata?.filesScanned} files)`);
    assert(scanResult.metadata.linesAnalyzed > 0, `metadata.linesAnalyzed is positive (${scanResult.metadata?.linesAnalyzed} lines)`);
    assert(typeof scanResult.metadata.durationMs === 'number', 'metadata.durationMs is recorded');

    // 4b: Validate Summary
    assert(scanResult.summary !== undefined, 'Response includes summary object');
    assert(typeof scanResult.summary.total === 'number', `summary.total is number (${scanResult.summary?.total})`);
    assert(
      scanResult.summary.total ===
        (scanResult.summary.critical + scanResult.summary.high + scanResult.summary.medium + scanResult.summary.low),
      'summary total equals sum of individual severities'
    );

    // 4c: Validate Findings Array
    assert(Array.isArray(scanResult.findings), `findings is an array (${scanResult.findings?.length} findings)`);
    assert(scanResult.findings.length === scanResult.summary.total, 'findings array length matches summary.total');

    if (scanResult.findings.length > 0) {
      const sample = scanResult.findings[0];
      assert(typeof sample.id === 'string' && sample.id.startsWith('cg-'), 'Finding has valid ID prefix');
      assert(['critical', 'high', 'medium', 'low'].includes(sample.severity), 'Finding has valid severity');
      assert(['secret', 'injection', 'dependency', 'validation'].includes(sample.category), 'Finding has valid category');
      assert(typeof sample.filePath === 'string', 'Finding has filePath');
      assert(sample.codeSnippet && Array.isArray(sample.codeSnippet.lines), 'Finding includes codeSnippet with lines');
    }

    // 4d: Validate Attack Graph
    assert(scanResult.graph !== undefined, 'Response includes attack-path graph');
    assert(Array.isArray(scanResult.graph.nodes), `graph.nodes is an array (${scanResult.graph?.nodes.length} nodes)`);
    assert(Array.isArray(scanResult.graph.edges), `graph.edges is an array (${scanResult.graph?.edges.length} edges)`);

    for (const node of scanResult.graph.nodes) {
      assert(['file', 'vulnerability', 'source'].includes(node.type), `Graph node ${node.id} has valid type: ${node.type}`);
    }
  } catch (err) {
    assert(false, `Real repository scan failed: ${err.message}`);
  }

  // Test Suite 5: Temporary Storage Cleanup Verification
  console.log('\nTest Suite 5: Temporary Directory Cleanup Verification');
  try {
    const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
    if (fs.existsSync(tempBaseDir)) {
      const remainingItems = fs.readdirSync(tempBaseDir);
      assert(
        remainingItems.length === 0,
        `Temp folder os.tmpdir()/codeguard-scans has 0 lingering scan directories (found: ${remainingItems.length})`
      );
    } else {
      assert(true, 'Temp scan directory was completely purged from os.tmpdir()');
    }
  } catch (err) {
    assert(false, `Temp directory cleanup check failed: ${err.message}`);
  }

  // Test Suite 6: Consecutive Multi-Run Cleanup Verification (3x Repeated Scans of expressjs/cors)
  console.log('\nTest Suite 6: Consecutive Multi-Run Cleanup Verification (3x Repeated Scans)');
  try {
    const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
    for (let run = 1; run <= 3; run++) {
      const resScan = await fetch(`${BASE_URL}/api/scan/repo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: TARGET_REPO }),
      });
      assert(resScan.status === 200, `Repository scan run ${run}/3 for '${TARGET_REPO}' completed with 200 OK`);
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
    assert(false, `Consecutive repo scan cleanup verification error: ${err.message}`);
  }

  // Summary Report
  console.log('\n====================================================');
  console.log(` Verification Summary: ${passedTests}/${totalTests} Passed (${failedTests} Failed)`);
  console.log('====================================================');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runRepoScanVerification().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
