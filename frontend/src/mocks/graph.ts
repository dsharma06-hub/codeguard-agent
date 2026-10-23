import type { AttackGraphData } from '../types/finding';

export const mockAttackGraph: AttackGraphData = {
  nodes: [
    // File Nodes
    { id: 'file:src/config/aws.client.ts', type: 'file', label: 'src/config/aws.client.ts' },
    { id: 'file:src/controllers/user.controller.ts', type: 'file', label: 'src/controllers/user.controller.ts' },
    { id: 'file:package.json', type: 'file', label: 'package.json' },
    { id: 'file:src/services/webhook.ts', type: 'file', label: 'src/services/webhook.ts' },
    { id: 'file:src/middleware/auth.ts', type: 'file', label: 'src/middleware/auth.ts' },
    { id: 'file:src/routes/auth.ts', type: 'file', label: 'src/routes/auth.ts' },
    { id: 'file:src/views/search.view.tsx', type: 'file', label: 'src/views/search.view.tsx' },

    // Untrusted Sources
    { id: 'source:cg-sec-002:req.query.filter', type: 'source', label: 'req.query.filter' },
    { id: 'source:cg-sec-004:req.body.targetUrl', type: 'source', label: 'req.body.targetUrl' },
    { id: 'source:cg-sec-006:req.query.returnTo', type: 'source', label: 'req.query.returnTo' },
    { id: 'source:cg-sec-007:window.location.search', type: 'source', label: 'window.location.search' },

    // Vulnerability Nodes
    {
      id: 'vuln:cg-sec-001',
      type: 'vulnerability',
      label: 'Hardcoded Production AWS Secret Key',
      severity: 'critical',
      category: 'secret',
    },
    {
      id: 'vuln:cg-sec-002',
      type: 'vulnerability',
      label: 'SQL Injection via Unsanitized Query Interpolation',
      severity: 'critical',
      category: 'injection',
    },
    {
      id: 'vuln:cg-sec-003',
      type: 'vulnerability',
      label: 'Remote Code Execution via Prototype Pollution in lodash',
      severity: 'high',
      category: 'dependency',
    },
    {
      id: 'vuln:cg-sec-004',
      type: 'vulnerability',
      label: 'Server-Side Request Forgery (SSRF) via Axios Client',
      severity: 'high',
      category: 'injection',
    },
    {
      id: 'vuln:cg-sec-005',
      type: 'vulnerability',
      label: 'Algorithm Confusion in JWT Signature Verification',
      severity: 'medium',
      category: 'secret',
    },
    {
      id: 'vuln:cg-sec-006',
      type: 'vulnerability',
      label: 'Unvalidated Open Redirection in Authentication Flow',
      severity: 'low',
      category: 'validation',
    },
    {
      id: 'vuln:cg-sec-007',
      type: 'vulnerability',
      label: 'DOM Cross-Site Scripting via element.innerHTML',
      severity: 'critical',
      category: 'Cross-Site Scripting',
    },
  ],
  edges: [
    // cg-sec-001: secret -> file
    { id: 'edge:vuln:cg-sec-001->file:src/config/aws.client.ts', source: 'vuln:cg-sec-001', target: 'file:src/config/aws.client.ts', label: 'found in' },

    // cg-sec-002: source -> vuln -> file
    { id: 'edge:source:cg-sec-002->vuln:cg-sec-002', source: 'source:cg-sec-002:req.query.filter', target: 'vuln:cg-sec-002', label: 'flows into' },
    { id: 'edge:vuln:cg-sec-002->file:src/controllers/user.controller.ts', source: 'vuln:cg-sec-002', target: 'file:src/controllers/user.controller.ts', label: 'found in' },

    // cg-sec-003: dependency -> file
    { id: 'edge:vuln:cg-sec-003->file:package.json', source: 'vuln:cg-sec-003', target: 'file:package.json', label: 'found in' },

    // cg-sec-004: source -> vuln -> file
    { id: 'edge:source:cg-sec-004->vuln:cg-sec-004', source: 'source:cg-sec-004:req.body.targetUrl', target: 'vuln:cg-sec-004', label: 'flows into' },
    { id: 'edge:vuln:cg-sec-004->file:src/services/webhook.ts', source: 'vuln:cg-sec-004', target: 'file:src/services/webhook.ts', label: 'found in' },

    // cg-sec-005: vuln -> file
    { id: 'edge:vuln:cg-sec-005->file:src/middleware/auth.ts', source: 'vuln:cg-sec-005', target: 'file:src/middleware/auth.ts', label: 'found in' },

    // cg-sec-006: source -> vuln -> file
    { id: 'edge:source:cg-sec-006->vuln:cg-sec-006', source: 'source:cg-sec-006:req.query.returnTo', target: 'vuln:cg-sec-006', label: 'flows into' },
    { id: 'edge:vuln:cg-sec-006->file:src/routes/auth.ts', source: 'vuln:cg-sec-006', target: 'file:src/routes/auth.ts', label: 'found in' },

    // cg-sec-007: source -> vuln -> file
    { id: 'edge:source:cg-sec-007->vuln:cg-sec-007', source: 'source:cg-sec-007:window.location.search', target: 'vuln:cg-sec-007', label: 'flows into' },
    { id: 'edge:vuln:cg-sec-007->file:src/views/search.view.tsx', source: 'vuln:cg-sec-007', target: 'file:src/views/search.view.tsx', label: 'found in' },
  ],
};
