import fs from 'fs';
import path from 'path';
import os from 'os';
import AdmZip from 'adm-zip';

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';

async function run() {
  console.log('====================================================');
  console.log(' CodeGuard Python XSS & SSTI Scanning Verification');
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

  // 1. Create a zip codebase containing vulnerable and clean Python XSS/SSTI code
  const zip = new AdmZip();

  const vulnerablePython = `
from flask import request, render_template_string
from markupsafe import Markup, escape
from django.utils.safestring import mark_safe

def ssti_view():
    user = request.args.get("name")
    return render_template_string(f"<h1>Hello {user}</h1>")

def markup_view():
    comment = request.form.get("comment")
    return Markup(comment)

def mark_safe_view():
    bio = request.POST.get("bio")
    return mark_safe(bio)

def eval_view():
    calc = request.args.get("calc")
    return eval(calc)

def sanitized_markup_view():
    title = request.args.get("title")
    clean = escape(title)
    return Markup(clean)
`;

  const cleanPython = `
from flask import request, render_template, render_template_string
from markupsafe import Markup
from django.utils.safestring import mark_safe

def safe_render_template_file():
    user = request.args.get("name")
    return render_template("profile.html", user=user)

def safe_render_template_string_context():
    user = request.args.get("name")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=user)

def safe_markup_static():
    return Markup("<b>Static HTML content</b>")

def safe_mark_safe_static():
    return mark_safe("<p>Safe static message</p>")

def safe_eval_static():
    return eval("1 + 1")
`;

  zip.addFile('app/views.py', Buffer.from(vulnerablePython, 'utf-8'));
  zip.addFile('app/safe_views.py', Buffer.from(cleanPython, 'utf-8'));
  const zipBuffer = zip.toBuffer();

  const formData = new FormData();
  const fileBlob = new Blob([zipBuffer], { type: 'application/zip' });
  formData.append('file', fileBlob, 'python-xss-test.zip');

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
  assert(vulnFindings.length === 5, `Found exactly 5 findings in app/views.py (found: ${vulnFindings.length})`);

  // Verify False Positives in app/safe_views.py
  const safeFindings = findings.filter(f => f.filePath === 'app/safe_views.py');
  assert(
    safeFindings.length === 0,
    `0 false positive findings in app/safe_views.py (render_template & static Markup) (found: ${safeFindings.length})`
  );

  // 1. SSTI finding verification
  const sstiF = vulnFindings.find(f => f.title.includes('Server-Side Template Injection') || f.cwe === 'CWE-1336');
  assert(sstiF !== undefined, 'Found SSTI in render_template_string');
  if (sstiF) {
    assert(sstiF.severity === 'critical', `SSTI severity is 'critical' (${sstiF.severity})`);
    assert(sstiF.cwe === 'CWE-1336', `SSTI CWE is 'CWE-1336' (${sstiF.cwe})`);
    assert(sstiF.category === 'injection', `Category mapped to 'injection' (${sstiF.category})`);
    assert(sstiF.codeSnippet.language === 'python', `Snippet language is 'python' (${sstiF.codeSnippet.language})`);
    assert(sstiF.sourceExpression.includes('request.args.get'), 'Source points to request.args.get');
    assert(sstiF.sinkExpression === 'render_template_string', 'Sink points to render_template_string');
  }

  // 2. Markup XSS finding verification
  const markupF = vulnFindings.find(f => f.title.includes('Markup() Autoescaping Bypass') && f.severity === 'critical');
  assert(markupF !== undefined, 'Found raw Markup() autoescaping bypass');
  if (markupF) {
    assert(markupF.cwe === 'CWE-79', `Markup CWE is 'CWE-79' (${markupF.cwe})`);
    assert(markupF.category === 'injection', `Category mapped to 'injection' (${markupF.category})`);
    assert(markupF.sourceExpression.includes('request.form.get'), 'Source points to request.form.get');
  }

  // 3. mark_safe XSS finding verification
  const markSafeF = vulnFindings.find(f => f.title.includes('mark_safe() Autoescaping Bypass') && f.severity === 'critical');
  assert(markSafeF !== undefined, 'Found raw mark_safe() autoescaping bypass');
  if (markSafeF) {
    assert(markSafeF.cwe === 'CWE-79', `mark_safe CWE is 'CWE-79' (${markSafeF.cwe})`);
    assert(markSafeF.category === 'injection', `Category mapped to 'injection' (${markSafeF.category})`);
  }

  // 4. eval() Code Injection finding verification
  const evalF = vulnFindings.find(f => f.cwe === 'CWE-95' || f.title.includes('eval()'));
  assert(evalF !== undefined, 'Found eval() code injection');
  if (evalF) {
    assert(evalF.severity === 'critical', `eval severity is 'critical' (${evalF.severity})`);
    assert(evalF.cwe === 'CWE-95', `eval CWE is 'CWE-95' (${evalF.cwe})`);
  }

  // 5. Sanitized Markup finding verification (Medium severity)
  const sanitizedF = vulnFindings.find(f => f.title.includes('Sanitizer Detected') && f.severity === 'medium');
  assert(sanitizedF !== undefined, 'Found sanitized Markup() downgraded to medium severity');
  if (sanitizedF) {
    assert(sanitizedF.severity === 'medium', `Sanitized severity is 'medium' (${sanitizedF.severity})`);
    assert(sanitizedF.description.includes('escape'), 'Description references escape sanitizer');
  }

  // Verify Attack Graph
  const graph = data.graph || { nodes: [], edges: [] };
  assert(Array.isArray(graph.nodes) && graph.nodes.length > 0, `Attack graph generated with ${graph.nodes.length} nodes`);
  assert(
    graph.nodes.some(n => n.type === 'file' && n.label === 'app/views.py'),
    `Attack graph contains Python file node 'app/views.py'`
  );
  assert(
    graph.nodes.some(n => n.type === 'source'),
    `Attack graph contains source node for tainted user input`
  );
  assert(
    graph.edges.some(e => e.label === 'flows into'),
    `Attack graph contains 'flows into' edges linking source -> vulnerability`
  );

  // 6. 3-run consecutive cleanup check
  console.log('\nRunning 3 consecutive scan iterations to verify 0 leftover directories...');
  const tempBaseDir = path.join(os.tmpdir(), 'codeguard-scans');
  for (let run = 1; run <= 3; run++) {
    const loopFormData = new FormData();
    const loopBlob = new Blob([zipBuffer], { type: 'application/zip' });
    loopFormData.append('file', loopBlob, 'python-xss-consecutive.zip');

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
