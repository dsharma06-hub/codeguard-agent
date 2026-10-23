/**
 * Graph Service: Synthesizes an attack-path graph model from security findings.
 *
 * Graph Model:
 * - Nodes:
 *   - "file": Unique file involved in a finding (deduplicated)
 *   - "vulnerability": Security finding with its severity and category
 *   - "source": Tainted user input source (for SQL injection findings with source data)
 * - Edges:
 *   - source -> vulnerability ("flows into")
 *   - vulnerability -> file ("found in")
 */

/**
 * Transforms flat security findings into an attack-path graph structure
 *
 * @param {Array<Object>} findings - Normalized findings array
 * @returns {{ nodes: Array<Object>, edges: Array<Object> }}
 */
export function buildAttackGraph(findings = []) {
  const fileNodesMap = new Map();
  const sourceNodes = [];
  const vulnNodes = [];
  const edges = [];

  for (const finding of findings) {
    const vulnNodeId = `vuln:${finding.id}`;

    // 1. File Node: Each unique file involved in a finding becomes a node
    const filePath = finding.filePath;
    const fileNodeId = `file:${filePath}`;
    if (!fileNodesMap.has(fileNodeId)) {
      fileNodesMap.set(fileNodeId, {
        id: fileNodeId,
        type: 'file',
        label: filePath,
      });
    }

    // 2. Vulnerability Node: Each finding becomes a node carrying severity & category
    const vulnNode = {
      id: vulnNodeId,
      type: 'vulnerability',
      label: finding.title,
      severity: finding.severity,
      category: finding.category,
    };
    vulnNodes.push(vulnNode);

    // 3. Source Node: For SQL injection findings specifically, the tainted input source
    if (finding.category === 'injection' && finding.sourceExpression) {
      const sourceNodeId = `source:${finding.id}:${finding.sourceExpression}`;
      const sourceNode = {
        id: sourceNodeId,
        type: 'source',
        label: finding.sourceExpression,
      };
      sourceNodes.push(sourceNode);

      // Edge: source -> vulnerability ("flows into")
      edges.push({
        id: `edge:${sourceNodeId}->${vulnNodeId}`,
        source: sourceNodeId,
        target: vulnNodeId,
        label: 'flows into',
      });
    }

    // 4. Edge: vulnerability -> file ("found in")
    edges.push({
      id: `edge:${vulnNodeId}->${fileNodeId}`,
      source: vulnNodeId,
      target: fileNodeId,
      label: 'found in',
    });
  }

  // Combine nodes preserving logical traversal order: files, sources, vulnerabilities
  const nodes = [
    ...fileNodesMap.values(),
    ...sourceNodes,
    ...vulnNodes,
  ];

  return {
    nodes,
    edges,
  };
}
