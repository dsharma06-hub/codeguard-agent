import fs from 'fs';
import path from 'path';
import os from 'os';
import AdmZip from 'adm-zip';

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';

async function run() {
  console.log('====================================================');
  console.log(' CodeGuard Python Dependency Scanning Verification');
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

  // Build a test zip in memory
  const zip = new AdmZip();

  const prodReqs = `# Production requirements
django == 3.2.0
requests >= 2.0.0, < 2.30.0
flask
`;

  const devReqs = `# Dev requirements
requests == 2.25.0
`;

  const pyprojectToml = `[project]
name = "demo-python-app"
version = "0.1.0"
dependencies = [
    "pyyaml == 5.3",
]
`;

  const safeReqs = `# Safe requirements (must yield 0 findings)
django >= 3.2.14
requests == 2.31.0
urllib3 == 2.0.6
django-cors-headers == 3.2.0
`;

  zip.addFile('requirements.txt', Buffer.from(prodReqs, 'utf-8'));
  zip.addFile('requirements-dev.txt', Buffer.from(devReqs, 'utf-8'));
  zip.addFile('pyproject.toml', Buffer.from(pyprojectToml, 'utf-8'));
  zip.addFile('safe-requirements.txt', Buffer.from(safeReqs, 'utf-8'));
  const zipBuffer = zip.toBuffer();

  const formData = new FormData();
  const fileBlob = new Blob([zipBuffer], { type: 'application/zip' });
  formData.append('file', fileBlob, 'python-dependencies-test.zip');

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

  assert(filesScanned === 4, `Discovered and scanned 4 Python dependency files (found: ${filesScanned})`);

  // 1. Check requirements.txt findings
  const prodFindings = findings.filter(f => f.filePath === 'requirements.txt');
  assert(prodFindings.length === 3, `Found 3 findings in requirements.txt (found: ${prodFindings.length})`);

  const djangoF = prodFindings.find(f => f.title.includes('django'));
  assert(djangoF !== undefined, 'Found vulnerable Django finding in requirements.txt');
  if (djangoF) {
    assert(djangoF.severity === 'critical', `Django severity is 'critical' (${djangoF.severity})`);
    assert(djangoF.category === 'dependency', `Category mapped to 'dependency' (${djangoF.category})`);
    assert(djangoF.cwe === 'CWE-89', `CWE is 'CWE-89' (${djangoF.cwe})`);
  }

  const requestsF = prodFindings.find(f => f.title.includes('requests'));
  assert(requestsF !== undefined, 'Found vulnerable Requests finding in requirements.txt');
  if (requestsF) {
    assert(requestsF.severity === 'high', `Requests severity is 'high' (${requestsF.severity})`);
    assert(requestsF.cwe === 'CWE-200', `CWE is 'CWE-200' (${requestsF.cwe})`);
  }

  const flaskF = prodFindings.find(f => f.title.includes('flask'));
  assert(flaskF !== undefined, 'Found unpinned Flask finding in requirements.txt');
  if (flaskF) {
    assert(flaskF.severity === 'high', `Unpinned Flask severity is 'high' (${flaskF.severity})`);
    assert(flaskF.cwe === 'CWE-1104', `CWE is 'CWE-1104' (${flaskF.cwe})`);
  }

  // 2. Check requirements-dev.txt (severity reduction)
  const devFindings = findings.filter(f => f.filePath === 'requirements-dev.txt');
  assert(devFindings.length === 1, `Found 1 finding in requirements-dev.txt (found: ${devFindings.length})`);
  const devRequestsF = devFindings[0];
  if (devRequestsF) {
    assert(devRequestsF.severity === 'medium', `Dev dependency Requests downgraded to 'medium' (${devRequestsF.severity})`);
  }

  // 3. Check pyproject.toml findings
  const tomlFindings = findings.filter(f => f.filePath === 'pyproject.toml');
  assert(tomlFindings.length === 1, `Found 1 finding in pyproject.toml (found: ${tomlFindings.length})`);
  const pyyamlF = tomlFindings[0];
  if (pyyamlF) {
    assert(pyyamlF.severity === 'critical', `PyYAML severity is 'critical' (${pyyamlF.severity})`);
    assert(pyyamlF.cwe === 'CWE-502', `CWE is 'CWE-502' (${pyyamlF.cwe})`);
    assert(pyyamlF.codeSnippet?.language === 'toml', `Code snippet language is 'toml' (${pyyamlF.codeSnippet?.language})`);
  }

  // 4. Check safe-requirements.txt has 0 findings (false-positive prevention)
  const safeFindings = findings.filter(f => f.filePath === 'safe-requirements.txt');
  assert(safeFindings.length === 0, `0 false-positive findings in safe-requirements.txt (found: ${safeFindings.length})`);

  // 5. Attack Graph Verification
  const graph = data.graph || { nodes: [], edges: [] };
  assert(Array.isArray(graph.nodes) && graph.nodes.length > 0, `Attack graph generated with ${graph.nodes.length} nodes`);
  assert(
    graph.nodes.some(n => n.type === 'file' && n.label === 'requirements.txt'),
    `Attack graph contains file node 'requirements.txt'`
  );
  assert(
    graph.nodes.some(n => n.type === 'file' && n.label === 'pyproject.toml'),
    `Attack graph contains file node 'pyproject.toml'`
  );

  // 6. 3-run consecutive cleanup check
  console.log('\nRunning 3 consecutive scan iterations to verify 0 leftover directories...');
  const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
  for (let run = 1; run <= 3; run++) {
    const loopFormData = new FormData();
    const loopBlob = new Blob([zipBuffer], { type: 'application/zip' });
    loopFormData.append('file', loopBlob, 'python-deps-consecutive.zip');

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
