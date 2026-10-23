import assert from 'assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { runPlannerAgent } from '../agents/plannerAgent.js';
import { runVerifierAgent } from '../agents/verifierAgent.js';
import { runFixAgent, fixesStore } from '../agents/fixAgent.js';
import {
  runAgenticOrchestrator,
  approveFix,
  rejectFix,
  getScanFixes,
  emitAgentTrace,
  traceHistoryStore,
} from '../agents/orchestrator.js';

async function runTests() {
  console.log('--- Running Agentic Layer Verification Tests ---');

  const testTempDir = path.join(os.tmpdir(), `cg_test_agents_${Date.now()}`);
  fs.mkdirSync(path.join(testTempDir, 'src'), { recursive: true });

  const vulnerableFile = path.join(testTempDir, 'src', 'db.ts');
  fs.writeFileSync(
    vulnerableFile,
    `import { db } from './conn';\nexport function getUser(userId: string) {\n  const query = "SELECT * FROM users WHERE id = '" + userId + "'";\n  return db.query(query);\n}\n`
  );

  const cleanFile = path.join(testTempDir, 'src', 'clean.ts');
  fs.writeFileSync(
    cleanFile,
    `export const APP_NAME = "CodeGuard";\nconsole.log(APP_NAME);\n`
  );

  const targetFiles = [
    {
      fullPath: vulnerableFile,
      relPath: 'src/db.ts',
      ext: '.ts',
      isDependencyFile: false,
    },
    {
      fullPath: cleanFile,
      relPath: 'src/clean.ts',
      ext: '.ts',
      isDependencyFile: false,
    },
  ];

  const traces = [];
  const onTrace = (t) => traces.push(t);

  // 1. Test Planner Agent
  console.log('1. Testing Planner Agent...');
  const plannerRes = await runPlannerAgent(targetFiles, testTempDir, { onTrace });
  assert.ok(Array.isArray(plannerRes.chosenTools), 'Planner should return chosenTools array');
  assert.ok(plannerRes.chosenTools.length > 0, 'Planner should select at least 1 tool');
  assert.ok(traces.some(t => t.agent === 'Planner' && t.step === 'tool_call'), 'Planner should emit tool_call events');
  console.log('   ✓ Planner selected tools:', plannerRes.chosenTools);

  // 2. Test Verifier Agent
  console.log('2. Testing Verifier Agent...');
  const mockFinding = {
    id: 'cg-inj-001',
    title: 'SQL Injection',
    category: 'injection',
    filePath: 'src/db.ts',
    startLine: 3,
    endLine: 3,
    description: 'String concatenation in query',
    remediation: 'Use parameterized queries',
  };

  const verified = await runVerifierAgent([mockFinding], testTempDir, { onTrace });
  assert.strictEqual(verified.length, 1);
  assert.ok(verified[0].status === 'verified' || verified[0].status === 'dismissed', 'Finding must have status verified or dismissed');
  assert.ok(typeof verified[0].verifierConfidence === 'number', 'Finding must have numeric verifier confidence');
  console.log('   ✓ Verifier evaluated finding:', verified[0].status, `(${verified[0].verifierConfidence})`);

  // 3. Test Fix Agent (ReAct loop & human-in-the-loop pending state)
  console.log('3. Testing Fix Agent...');
  const scanId = `scan_test_${Date.now()}`;
  const fixes = await runFixAgent([verified[0]], testTempDir, { scanId, onTrace });
  assert.ok(Array.isArray(fixes), 'Fixes should be an array');
  assert.strictEqual(fixes.length, 1);
  const fix = fixes[0];
  assert.strictEqual(fix.status, 'pending', 'Fix status MUST be pending (Human-in-the-loop)');
  assert.ok(Array.isArray(fix.iterations), 'Fix must record ReAct iteration history');
  assert.ok(fix.iterations.length >= 1, 'Fix must have at least 1 ReAct iteration');
  assert.ok(typeof fix.diff === 'string' && fix.diff.length > 0, 'Fix must generate a diff');
  console.log('   ✓ Fix Agent proposed pending fix with', fix.iterations.length, 'ReAct iterations');

  // 4. Test Orchestrator & Human-in-the-Loop Approval
  console.log('4. Testing Human-in-the-Loop Approval & Rejection...');
  const orchestratorResult = await runAgenticOrchestrator(testTempDir, targetFiles, {
    scanId,
    repoName: 'test-repo',
  });

  assert.ok(orchestratorResult.findings, 'Orchestrator returns findings');
  assert.ok(orchestratorResult.fixes, 'Orchestrator returns fixes');
  assert.ok(orchestratorResult.agentTrace, 'Orchestrator returns agent trace');

  const pendingFixes = getScanFixes(scanId);
  assert.ok(pendingFixes.length > 0, 'Found pending fixes for scan');
  const targetFixId = pendingFixes[0].id;

  // Approve the fix
  const approvalRes = approveFix(targetFixId);
  assert.strictEqual(approvalRes.success, true);
  assert.strictEqual(approvalRes.fix.status, 'approved', 'Fix must be marked approved');

  // Verify file on disk was patched
  const patchedOnDisk = fs.readFileSync(path.join(testTempDir, approvalRes.fix.filePath), 'utf8');
  assert.strictEqual(patchedOnDisk, approvalRes.fix.patchedCode, 'Approved patch was written to ephemeral file copy');
  console.log('   ✓ Fix approved and applied to ephemeral codebase copy');

  // Reject a fix test
  const dummyFixId = `dummy_${Date.now()}`;
  fixesStore.set(dummyFixId, { id: dummyFixId, scanId, status: 'pending' });
  const rejectRes = rejectFix(dummyFixId);
  assert.strictEqual(rejectRes.fix.status, 'rejected', 'Fix must be marked rejected');
  console.log('   ✓ Fix rejection works');

  // 5. Test Agent Trace event streaming
  console.log('5. Testing Agent Trace SSE buffer...');
  emitAgentTrace(scanId, {
    agent: 'Orchestrator',
    step: 'test_event',
    tool: 'sse_test',
    input_summary: 'test input',
    output_summary: 'test output',
  });
  const storedTraces = traceHistoryStore.get(scanId);
  assert.ok(storedTraces.some(t => t.step === 'test_event'), 'Trace event was stored in buffer');
  console.log('   ✓ Trace event recorded in history buffer');

  // Cleanup
  fs.rmSync(testTempDir, { recursive: true, force: true });
  console.log('All backend agent unit tests PASSED successfully!\n');
}

runTests().catch(err => {
  console.error('Agent unit tests failed:', err);
  process.exit(1);
});
