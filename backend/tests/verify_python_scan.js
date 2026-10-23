import fs from 'fs';
import path from 'path';
import os from 'os';
import AdmZip from 'adm-zip';

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';

async function run() {
  console.log('====================================================');
  console.log(' CodeGuard Python Secrets Scanning Verification');
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

  // 1. Build a multi-language zip with TypeScript, Python, and ignored virtual environments
  const zip = new AdmZip();
  
  // TS secret
  zip.addFile(
    'src/config.ts',
    Buffer.from('export const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\nexport const PORT = 3000;\n')
  );

  // Python secrets
  zip.addFile(
    'services/auth.py',
    Buffer.from(
      '# Auth service\n' +
      'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n' +
      'client_secret = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"\n' +
      'def connect():\n' +
      '    return True\n'
    )
  );

  // Clean Python file with os.environ and docstring
  zip.addFile(
    'services/clean.py',
    Buffer.from(
      '"""Docstring containing AKIAIOSFODNN7EXAMPLE."""\n' +
      'import os\n' +
      'API_KEY = os.environ["STRIPE_KEY"]\n' +
      'DUMMY = "your-secret-key-here"\n' +
      'HEADERS = {"key": "Access-Control-Allow-Origin"}\n'
    )
  );

  // Vulnerable package.json
  zip.addFile(
    'package.json',
    Buffer.from(JSON.stringify({
      name: 'multi-lang-app',
      dependencies: {
        'lodash': '4.17.15',
      },
    }, null, 2))
  );

  // Ignored Python directories (must NOT be scanned or flagged)
  zip.addFile(
    '.venv/lib/python3.11/site-packages/leak.py',
    Buffer.from('LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
  );
  zip.addFile(
    'venv/leak2.py',
    Buffer.from('LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
  );
  zip.addFile(
    'myapp.egg-info/PKG-INFO.py',
    Buffer.from('LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
  );
  zip.addFile(
    '__pycache__/cached.py',
    Buffer.from('LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
  );

  const zipBuffer = zip.toBuffer();

  // 2. Submit zip to POST /api/scan/upload
  const formData = new FormData();
  formData.append(
    'file',
    new Blob([zipBuffer], { type: 'application/zip' }),
    'multi-lang-app.zip'
  );

  const res = await fetch(`${BACKEND_URL}/api/scan/upload`, {
    method: 'POST',
    body: formData,
  });

  assert(res.status === 200, `POST /api/scan/upload responds with 200 OK (status: ${res.status})`);
  
  const data = await res.json();
  const findings = data.findings || [];
  const metadata = data.metadata || {};

  console.log(`\nMetadata files scanned: ${metadata.filesScanned}`);
  console.log(`Total findings returned: ${findings.length}`);

  // Ignored directory assertion: filesScanned should be 4 (config.ts, auth.py, clean.py, package.json), NOT 8
  assert(
    metadata.filesScanned === 4,
    `Ignored directories (.venv, venv, *.egg-info, __pycache__) skipped (found: ${metadata.filesScanned}, expected: 4)`
  );

  // Python findings verification
  const pythonFindings = findings.filter(f => f.filePath === 'services/auth.py');
  assert(pythonFindings.length >= 2, `Found >= 2 secrets in services/auth.py (found: ${pythonFindings.length})`);

  const tsFindings = findings.filter(f => f.filePath === 'src/config.ts');
  assert(tsFindings.length >= 1, `Found >= 1 secret in src/config.ts (found: ${tsFindings.length})`);

  const cleanFindings = findings.filter(f => f.filePath === 'services/clean.py');
  assert(cleanFindings.length === 0, `0 false positive findings in services/clean.py (found: ${cleanFindings.length})`);

  // Snippet language verification
  for (const pyFinding of pythonFindings) {
    assert(
      pyFinding.codeSnippet?.language === 'python',
      `Python finding (${pyFinding.title}) code snippet language is 'python'`
    );
    assert(
      pyFinding.codeSnippet?.lines?.length > 0,
      `Python finding (${pyFinding.title}) code snippet contains contextual lines`
    );
    assert(
      pyFinding.category === 'secret',
      `Python finding category mapped to 'secret'`
    );
  }

  for (const tsFinding of tsFindings) {
    assert(
      tsFinding.codeSnippet?.language === 'typescript',
      `TypeScript finding snippet language is 'typescript'`
    );
  }

  // Attack graph verification
  const graph = data.graph || { nodes: [], edges: [] };
  assert(Array.isArray(graph.nodes) && graph.nodes.length > 0, `Attack graph generated with ${graph.nodes.length} nodes`);
  assert(
    graph.nodes.some(n => n.type === 'file' && n.label === 'services/auth.py'),
    `Attack graph contains Python file node 'services/auth.py'`
  );

  // Temp folder cleanup verification
  const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
  let leftoverCount = 0;
  if (fs.existsSync(tempBaseDir)) {
    leftoverCount = fs.readdirSync(tempBaseDir).length;
  }
  assert(
    leftoverCount === 0,
    `Temp folder os.tmpdir()/codeguard-scans has 0 lingering scan directories (found: ${leftoverCount})`
  );

  console.log('\n====================================================');
  console.log(` Verification Summary: ${passed}/${passed + failed} Passed (${failed} Failed)`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch(err => {
  console.error('Fatal error during verification:', err);
  process.exit(1);
});
