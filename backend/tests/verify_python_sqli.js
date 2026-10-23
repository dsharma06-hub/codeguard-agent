import fs from 'fs';
import path from 'path';
import os from 'os';
import AdmZip from 'adm-zip';

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';

async function run() {
  console.log('====================================================');
  console.log(' CodeGuard Python SQL Injection Scanning Verification');
  console.log(` Target Backend URL: ${BACKEND_URL}`);
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✓ ${message}`);
      passed++;
    } else {
      console.error(`  ✗ ${message}`);
      failed++;
    }
  }

  // 1. Create a zip codebase containing vulnerable and clean Python SQL code
  const zip = new AdmZip();

  const vulnerablePython = `
from flask import request
from django.db import connection

def get_user_dbapi():
    user_id = request.args.get("id")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def get_user_django_raw(User):
    name = request.args.get("name")
    return User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

def get_user_django_extra(User):
    role = request.args.get("role")
    return User.objects.extra(where=[f"role = '{role}'"], params=["safe"])
`;

  const cleanPython = `
from flask import request
from django.db import connection

def safe_dbapi():
    user_id = request.args.get("id")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

def safe_django_filter(User):
    user_id = request.args.get("id")
    return User.objects.filter(id=user_id)

def safe_django_raw(User):
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = %s"
    return User.objects.raw(sql, [user_id])
`;

  zip.addFile('app/views.py', Buffer.from(vulnerablePython, 'utf-8'));
  zip.addFile('app/safe_queries.py', Buffer.from(cleanPython, 'utf-8'));
  const zipBuffer = zip.toBuffer();

  const formData = new FormData();
  const fileBlob = new Blob([zipBuffer], { type: 'application/zip' });
  formData.append('file', fileBlob, 'python-sqli-test.zip');

  const res = await fetch(`${BACKEND_URL}/api/scan/upload`, {
    method: 'POST',
    body: formData,
  });

  assert(res.status === 200, `POST /api/scan/upload responds with 200 OK (status: ${res.status})`);
  const data = await res.json();

  const findings = data.findings || [];
  const filesScanned = data.metadata?.filesScanned || 0;

  console.log(`\nMetadata files scanned: ${filesScanned}`);
  console.log(`Total findings returned: ${findings.length}`);

  assert(filesScanned === 2, `Scanned 2 target Python files (found: ${filesScanned})`);

  // Verify True Positives in app/views.py
  const vulnFindings = findings.filter(f => f.filePath === 'app/views.py');
  assert(vulnFindings.length === 3, `Found exactly 3 SQL injection findings in app/views.py (found: ${vulnFindings.length})`);

  // Verify False Positives in app/safe_queries.py
  const safeFindings = findings.filter(f => f.filePath === 'app/safe_queries.py');
  assert(safeFindings.length === 0, `0 false positive findings in app/safe_queries.py (found: ${safeFindings.length})`);

  // Verify findings attributes
  for (const f of vulnFindings) {
    assert(f.category === 'injection', `Finding '${f.title}' mapped to category 'injection'`);
    assert(f.severity === 'critical', `Finding '${f.title}' severity is 'critical'`);
    assert(f.cwe === 'CWE-89', `Finding '${f.title}' CWE is 'CWE-89'`);
    assert(f.codeSnippet?.language === 'python', `Finding snippet language is 'python'`);
    assert(typeof f.sourceExpression === 'string' && f.sourceExpression.length > 0, `Finding carries sourceExpression: ${f.sourceExpression}`);
    assert(typeof f.sourceLine === 'number' && f.sourceLine > 0, `Finding carries sourceLine: ${f.sourceLine}`);
    assert(typeof f.sinkExpression === 'string' && f.sinkExpression.length > 0, `Finding carries sinkExpression: ${f.sinkExpression}`);
    assert(typeof f.sinkLine === 'number' && f.sinkLine > 0, `Finding carries sinkLine: ${f.sinkLine}`);
  }

  // Attack graph verification
  const graph = data.graph || { nodes: [], edges: [] };
  assert(Array.isArray(graph.nodes) && graph.nodes.length > 0, `Attack graph generated with ${graph.nodes.length} nodes`);
  assert(
    graph.nodes.some(n => n.type === 'file' && n.label === 'app/views.py'),
    `Attack graph contains Python file node 'app/views.py'`
  );
  assert(
    graph.nodes.some(n => n.type === 'source' && n.label.includes('request.args.get')),
    `Attack graph contains source node for tainted user input`
  );
  assert(
    graph.edges.some(e => e.label === 'flows into'),
    `Attack graph contains 'flows into' edges linking source -> vulnerability`
  );

  // 3-run consecutive cleanup check
  console.log('\nRunning 3 consecutive scan iterations to verify 0 leftover directories...');
  const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
  for (let run = 1; run <= 3; run++) {
    const loopFormData = new FormData();
    const loopBlob = new Blob([zipBuffer], { type: 'application/zip' });
    loopFormData.append('file', loopBlob, 'python-sqli-consecutive.zip');

    const loopRes = await fetch(`${BACKEND_URL}/api/scan/upload`, {
      method: 'POST',
      body: loopFormData,
    });
    assert(loopRes.status === 200, `Consecutive run ${run}/3 completed with 200 OK`);

    let leftoverCount = 0;
    if (fs.existsSync(tempBaseDir)) {
      leftoverCount = fs.readdirSync(tempBaseDir).length;
    }
    assert(
      leftoverCount === 0,
      `Post-scan run ${run}/3 has 0 lingering scan directories (found: ${leftoverCount})`
    );
  }

  console.log('\n====================================================');
  console.log(` Verification Summary: ${passed}/${passed + failed} Passed (${failed} Failed)`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('Fatal error during verification:', err);
  process.exit(1);
});
