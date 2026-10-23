import assert from 'assert';
import AdmZip from 'adm-zip';

const BACKEND_URL = 'http://127.0.0.1:5000';

async function runTests() {
  console.log('========================================================');
  console.log(' CodeGuard: LLM Explanation Layer Verification Suite   ');
  console.log('========================================================\n');

  // Test 1: Explain real finding with live Gemini API
  console.log('Test 1: Requesting real AI explanation for SQL injection finding...');
  const testFinding = {
    id: 'cg-inj-test-001',
    title: 'SQL Injection via string formatting in execute()',
    category: 'injection',
    filePath: 'backend/routes/auth.py',
    startLine: 18,
    endLine: 18,
    description: 'User-controlled input flows directly into SQL query string formatting without parameterization.',
    remediation: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE username = %s", (username,))',
    cwe: 'CWE-89',
    codeSnippet: {
      language: 'python',
      startLine: 16,
      lines: [
        'def login():',
        '    username = request.form.get("username")',
        '    cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\'")',
        '    return cursor.fetchone()'
      ],
      highlightLines: [18],
      highlightMessage: 'Tainted parameter username reaching raw SQL sink'
    },
    sourceExpression: 'request.form.get("username")',
    sinkExpression: 'cursor.execute(...)'
  };

  const explainRes1 = await fetch(`${BACKEND_URL}/api/findings/${testFinding.id}/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding: testFinding,
      bypassCache: true
    })
  });

  assert.strictEqual(explainRes1.status, 200, `Expected 200 OK, got ${explainRes1.status}`);
  const data1 = await explainRes1.json();

  assert.strictEqual(data1.success, true, 'Expected success: true');
  assert.strictEqual(data1.isFallback, false, 'Expected isFallback: false for valid Gemini API call');
  assert.ok(data1.explanation.length > 50, 'Explanation should be substantial');
  assert.ok(
    data1.explanation.toLowerCase().includes("dangerous") || data1.explanation.toLowerCase().includes("risk"),
    'Explanation should detail why it is dangerous'
  );
  assert.ok(
    data1.explanation.toLowerCase().includes("fix") || data1.explanation.toLowerCase().includes("parameter"),
    'Explanation should detail how to fix it'
  );

  console.log('✓ Live Gemini explanation generated successfully');
  console.log(`  Model: ${data1.model}`);
  console.log(`  Cached: ${data1.cached}`);
  console.log(`  Preview:\n---\n${data1.explanation.slice(0, 260)}...\n---`);

  // Test 2: In-memory session cache hit
  console.log('\nTest 2: Verifying in-memory cache hit on subsequent call...');
  const explainRes2 = await fetch(`${BACKEND_URL}/api/findings/${testFinding.id}/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding: testFinding
    })
  });

  assert.strictEqual(explainRes2.status, 200, `Expected 200 OK, got ${explainRes2.status}`);
  const data2 = await explainRes2.json();
  assert.strictEqual(data2.cached, true, 'Expected cached: true on second lookup');
  assert.strictEqual(data2.isFallback, false, 'Expected isFallback: false');
  assert.strictEqual(data2.explanation, data1.explanation, 'Cached explanation should match first call');
  console.log('✓ Cache hit confirmed (0 API tokens consumed)');

  // Test 3: Fallback on invalid API key (never return 500, return 200 with standard guidance)
  console.log('\nTest 3: Verifying automatic fallback on API error (invalid key)...');
  const fallbackRes = await fetch(`${BACKEND_URL}/api/findings/test-invalid-key/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding: {
        id: 'test-invalid-key',
        title: 'Secret Exposure',
        category: 'secret',
        filePath: 'config.py',
        remediation: 'Store credentials in environment variables.',
        codeSnippet: { lines: ['API_KEY = "dummy"'] }
      },
      customApiKey: 'INVALID_TEST_KEY_SIMULATION',
      bypassCache: true
    })
  });

  assert.strictEqual(fallbackRes.status, 200, `Expected 200 OK even on API failure, got ${fallbackRes.status}`);
  const fallbackData = await fallbackRes.json();
  assert.strictEqual(fallbackData.success, true, 'Expected success: true');
  assert.strictEqual(fallbackData.isFallback, true, 'Expected isFallback: true');
  assert.strictEqual(fallbackData.fallbackReason, 'api_error', 'Expected fallbackReason: api_error');
  assert.strictEqual(fallbackData.explanation, 'Store credentials in environment variables.', 'Expected static remediation');
  console.log('✓ Fallback handled gracefully with status 200 & standard guidance');

  // Test 4: Fallback on timeout (<=8s limit)
  console.log('\nTest 4: Verifying automatic fallback on timeout (1ms forced timeout)...');
  const timeoutRes = await fetch(`${BACKEND_URL}/api/findings/test-timeout/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding: {
        id: 'test-timeout',
        title: 'DOM XSS',
        category: 'xss',
        filePath: 'client.js',
        remediation: 'Use textContent instead of innerHTML.',
        codeSnippet: { lines: ['element.innerHTML = userInput;'] }
      },
      timeoutMs: 1,
      bypassCache: true
    })
  });

  assert.strictEqual(timeoutRes.status, 200, `Expected 200 OK on timeout, got ${timeoutRes.status}`);
  const timeoutData = await timeoutRes.json();
  assert.strictEqual(timeoutData.success, true, 'Expected success: true');
  assert.strictEqual(timeoutData.isFallback, true, 'Expected isFallback: true');
  assert.strictEqual(timeoutData.fallbackReason, 'timeout', 'Expected fallbackReason: timeout');
  assert.strictEqual(timeoutData.explanation, 'Use textContent instead of innerHTML.');
  console.log('✓ Timeout fallback handled gracefully with status 200 & standard guidance');

  // Test 5: Scan integration (scan registers findings, explain endpoint resolves by ID)
  console.log('\nTest 5: Testing full scan integration (scan registers findings in store)...');
  const zip = new AdmZip();
  zip.addFile(
    'app.py',
    Buffer.from(`from flask import request, render_template_string

def render_page():
    user = request.args.get("name")
    return render_template_string(f"<h1>Hello {user}</h1>")
`)
  );
  const zipBuffer = zip.toBuffer();

  const form = new FormData();
  const blob = new Blob([zipBuffer], { type: 'application/zip' });
  form.append('file', blob, 'ssti_test.zip');

  const scanRes = await fetch(`${BACKEND_URL}/api/scan/upload`, {
    method: 'POST',
    body: form,
  });

  assert.strictEqual(scanRes.status, 200, `Scan failed with status ${scanRes.status}`);
  const scanData = await scanRes.json();
  assert.ok(scanData.findings.length > 0, 'Scan should detect findings');
  const firstFinding = scanData.findings[0];
  console.log(`✓ Scan completed with ${scanData.findings.length} finding(s). Picked ID: ${firstFinding.id}`);

  // Now call explain by finding ID WITHOUT passing finding in body!
  const scanExplainRes = await fetch(`${BACKEND_URL}/api/findings/${firstFinding.id}/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}) // Empty body tests store lookup!
  });

  assert.strictEqual(scanExplainRes.status, 200, `Expected 200 OK, got ${scanExplainRes.status}`);
  const scanExplainData = await scanExplainRes.json();
  assert.strictEqual(scanExplainData.success, true, 'Expected success: true');
  assert.strictEqual(scanExplainData.findingId, firstFinding.id, 'Expected correct findingId');
  assert.ok(scanExplainData.explanation.length > 30, 'Expected non-empty explanation');
  console.log(`✓ Store lookup by ID confirmed: isFallback=${scanExplainData.isFallback}`);

  console.log('\n========================================================');
  console.log(' ALL 5 LLM EXPLANATION TESTS PASSED SUCCESSFULLY!       ');
  console.log('========================================================');
}

runTests().catch((err) => {
  console.error('\n❌ Test suite failed:', err);
  process.exit(1);
});
