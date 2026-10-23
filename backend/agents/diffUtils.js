/**
 * Diff utility for computing line-by-line unified diffs without external dependencies.
 */

/**
 * Computes a unified diff between two text strings.
 * @param {string} oldText
 * @param {string} newText
 * @param {string} [fileName='file']
 * @returns {string} Unified diff representation
 */
export function computeUnifiedDiff(oldText = '', newText = '', fileName = 'file') {
  const oldLines = oldText.split(/\r?\n/);
  const newLines = newText.split(/\r?\n/);

  // Simple and robust LCS-based diff
  const n = oldLines.length;
  const m = newLines.length;

  // Build LCS matrix
  const matrix = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < m; j++) {
      if (oldLines[i] === newLines[j]) {
        matrix[i + 1][j + 1] = matrix[i][j] + 1;
      } else {
        matrix[i + 1][j + 1] = Math.max(matrix[i + 1][j], matrix[i][j + 1]);
      }
    }
  }

  // Backtrack to find edits
  let i = n;
  let j = m;
  const edits = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && oldLines[i - 1] === newLines[j - 1]) {
      edits.push({ type: 'equal', line: oldLines[i - 1], oldNum: i, newNum: j });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || matrix[i][j - 1] >= matrix[i - 1][j])) {
      edits.push({ type: 'add', line: newLines[j - 1], newNum: j });
      j--;
    } else if (i > 0 && (j === 0 || matrix[i][j - 1] < matrix[i - 1][j])) {
      edits.push({ type: 'delete', line: oldLines[i - 1], oldNum: i });
      i--;
    }
  }

  edits.reverse();

  // If identical
  if (!edits.some(e => e.type !== 'equal')) {
    return `--- a/${fileName}\n+++ b/${fileName}\n@@ -1,${n} +1,${m} @@\n (no changes)`;
  }

  // Format into unified diff lines
  const diffLines = [
    `--- a/${fileName}`,
    `+++ b/${fileName}`,
  ];

  let hunk = [];
  let inHunk = false;

  for (let idx = 0; idx < edits.length; idx++) {
    const edit = edits[idx];
    const isChange = edit.type !== 'equal';

    // Lookaround window of 3 lines
    const nearChange = edits.slice(Math.max(0, idx - 3), Math.min(edits.length, idx + 4))
      .some(e => e.type !== 'equal');

    if (nearChange) {
      if (!inHunk) {
        inHunk = true;
        diffLines.push('@@ ... @@');
      }
      const prefix = edit.type === 'add' ? '+' : edit.type === 'delete' ? '-' : ' ';
      diffLines.push(`${prefix} ${edit.line}`);
    } else if (inHunk) {
      inHunk = false;
    }
  }

  return diffLines.join('\n');
}
