import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BASE_URL = process.env.BACKEND_URL || 'http://localhost:5000';
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

async function verifyAttackGraph() {
  console.log('====================================================');
  console.log(' CodeGuard Attack-Path Graph Verification');
  console.log(' Target Backend URL:', BASE_URL);
  console.log('====================================================\n');

  if (!fs.existsSync(FIXTURE_ZIP_PATH)) {
    console.error(`Fixture not found at ${FIXTURE_ZIP_PATH}`);
    process.exit(1);
  }

  const zipBuffer = fs.readFileSync(FIXTURE_ZIP_PATH);
  const formData = new FormData();
  formData.append('file', new Blob([zipBuffer], { type: 'application/zip' }), 'sample-vulnerable-repo.zip');

  console.log('Uploading sample-vulnerable-repo.zip to /api/scan/upload...');
  const res = await fetch(`${BASE_URL}/api/scan/upload`, {
    method: 'POST',
    body: formData,
  });

  assert(res.status === 200, `POST /api/scan/upload responds with 200 OK`);
  const data = await res.json();

  assert(data.graph !== undefined, 'Response body contains "graph" field');
  const graph = data.graph || {};
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];

  assert(Array.isArray(nodes) && nodes.length > 0, `Graph contains nodes array (found ${nodes.length} nodes)`);
  assert(Array.isArray(edges) && edges.length > 0, `Graph contains edges array (found ${edges.length} edges)`);

  console.log('\n--- Evaluating Node & Edge Specifications ---');

  // 1. Check Node Types
  const fileNodes = nodes.filter((n) => n.type === 'file');
  const vulnNodes = nodes.filter((n) => n.type === 'vulnerability');
  const sourceNodes = nodes.filter((n) => n.type === 'source');

  console.log(`  Node distribution: ${fileNodes.length} files, ${sourceNodes.length} sources, ${vulnNodes.length} vulnerabilities`);
  assert(fileNodes.length > 0, 'Graph contains file nodes');
  assert(vulnNodes.length === 4, `Graph contains exactly 4 vulnerability nodes (found ${vulnNodes.length})`);
  assert(sourceNodes.length === 1, `Graph contains exactly 1 tainted source node for SQLi (found ${sourceNodes.length})`);

  // 2. Assert no duplicate file nodes
  const fileNodeIds = fileNodes.map((n) => n.id);
  const uniqueFileNodeIds = new Set(fileNodeIds);
  assert(
    fileNodeIds.length === uniqueFileNodeIds.size,
    `No duplicate file nodes (unique count: ${uniqueFileNodeIds.size}, total file nodes: ${fileNodeIds.length})`
  );
  assert(uniqueFileNodeIds.has('file:package.json'), 'file:package.json node exists once despite having 2 CVE findings');
  assert(uniqueFileNodeIds.has('file:src/config.ts'), 'file:src/config.ts node exists');
  assert(uniqueFileNodeIds.has('file:src/db.ts'), 'file:src/db.ts node exists');

  // 3. Verify SQL Injection 3-Node Chain: source -> vulnerability -> file
  console.log('\n--- Evaluating SQL Injection 3-Node Chain ---');
  const sqliVuln = vulnNodes.find((n) => n.category === 'injection');
  assert(Boolean(sqliVuln), 'SQL Injection vulnerability node exists');

  if (sqliVuln) {
    // Find edge from source -> sqliVuln
    const inEdge = edges.find((e) => e.target === sqliVuln.id && e.label === 'flows into');
    assert(Boolean(inEdge), `Incoming "flows into" edge exists targeting ${sqliVuln.id}`);

    if (inEdge) {
      const sourceNode = nodes.find((n) => n.id === inEdge.source);
      assert(Boolean(sourceNode), `Source node ${inEdge.source} exists in nodes array`);
      assert(sourceNode?.type === 'source', `Source node type is "source" (label: "${sourceNode?.label}")`);
      assert(sourceNode?.label === 'req.query.id', `Source node label is "req.query.id"`);
    }

    // Find edge from sqliVuln -> file
    const outEdge = edges.find((e) => e.source === sqliVuln.id && e.label === 'found in');
    assert(Boolean(outEdge), `Outgoing "found in" edge exists from ${sqliVuln.id}`);

    if (outEdge) {
      const targetFileNode = nodes.find((n) => n.id === outEdge.target);
      assert(targetFileNode?.id === 'file:src/db.ts', `SQL Injection connects to file:src/db.ts`);
      assert(targetFileNode?.type === 'file', `Target node type is "file"`);
    }
  }

  // 4. Verify Secret Finding 2-Node Chain: vulnerability -> file (NO source node)
  console.log('\n--- Evaluating Secret Leak 2-Node Chain ---');
  const secretVuln = vulnNodes.find((n) => n.category === 'secret');
  assert(Boolean(secretVuln), 'Secret leak vulnerability node exists');

  if (secretVuln) {
    const incomingEdges = edges.filter((e) => e.target === secretVuln.id);
    assert(incomingEdges.length === 0, 'Secret vulnerability node has NO incoming source edges (2-node chain)');

    const outEdge = edges.find((e) => e.source === secretVuln.id && e.label === 'found in');
    assert(Boolean(outEdge), `Outgoing "found in" edge exists for secret`);
    assert(outEdge?.target === 'file:src/config.ts', `Secret connects to file:src/config.ts`);
  }

  // 5. Verify Dependency Findings 2-Node Chains: vulnerability -> file (NO source node)
  console.log('\n--- Evaluating Vulnerable Dependency 2-Node Chains ---');
  const depVulns = vulnNodes.filter((n) => n.category === 'dependency');
  assert(depVulns.length === 2, `Found 2 dependency vulnerability nodes`);

  for (const depVuln of depVulns) {
    const incomingEdges = edges.filter((e) => e.target === depVuln.id);
    assert(incomingEdges.length === 0, `Dependency node ${depVuln.id} has NO incoming source edges`);

    const outEdge = edges.find((e) => e.source === depVuln.id && e.label === 'found in');
    assert(outEdge?.target === 'file:package.json', `${depVuln.id} connects to file:package.json`);
  }

  // 6. Print Full Attack-Path Graph Model
  console.log('\n====================================================');
  console.log(' Attack Graph Representation (JSON Structure)');
  console.log('====================================================');
  console.log(JSON.stringify(graph, null, 2));

  console.log('\n====================================================');
  console.log(' Attack-Path Chains Summary');
  console.log('====================================================');
  for (const vuln of vulnNodes) {
    const inEdge = edges.find((e) => e.target === vuln.id);
    const outEdge = edges.find((e) => e.source === vuln.id);
    const sourceNode = inEdge ? nodes.find((n) => n.id === inEdge.source) : null;
    const fileNode = outEdge ? nodes.find((n) => n.id === outEdge.target) : null;

    if (sourceNode) {
      console.log(`  [3-Node Chain] (source) ${sourceNode.label} ──[flows into]──> (vuln:${vuln.severity}) ${vuln.label} ──[found in]──> (file) ${fileNode?.label}`);
    } else {
      console.log(`  [2-Node Chain] (vuln:${vuln.severity}) ${vuln.label} ──[found in]──> (file) ${fileNode?.label}`);
    }
  }

  console.log('\n====================================================');
  console.log(` Verification Summary: ${passedTests}/${totalTests} Passed (${failedTests} Failed)`);
  console.log('====================================================');

  if (failedTests > 0) {
    process.exit(1);
  }
}

verifyAttackGraph().catch((err) => {
  console.error('Attack graph verification failed:', err);
  process.exit(1);
});
