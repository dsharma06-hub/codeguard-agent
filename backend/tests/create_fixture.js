import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import AdmZip from 'adm-zip';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fixturesDir = path.join(__dirname, 'fixtures');
fs.mkdirSync(fixturesDir, { recursive: true });

const zip = new AdmZip();

// 1. Hardcoded Secret in TypeScript
const configTs = `// CodeGuard Sample Repo - Configuration
export const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
export const APP_ENV = "production";
export const PORT = 8080;
`;
zip.addFile('src/config.ts', Buffer.from(configTs, 'utf8'));

// 2. SQL Injection in TypeScript
const dbTs = `// CodeGuard Sample Repo - Database Access
export async function findUserById(req: any, db: any) {
  const userId = req.query.id;
  const sql = "SELECT * FROM users WHERE id = '" + userId + "'";
  return await db.query(sql);
}
`;
zip.addFile('src/db.ts', Buffer.from(dbTs, 'utf8'));

// 3. Vulnerable Dependency in package.json
const packageJson = JSON.stringify(
  {
    name: "sample-vulnerable-repo",
    version: "1.0.0",
    dependencies: {
      "lodash": "4.17.15",
      "express": "^4.18.2"
    }
  },
  null,
  2
);
zip.addFile('package.json', Buffer.from(packageJson, 'utf8'));

// 4. Safe file with no vulnerabilities
const cleanTs = `// CodeGuard Sample Repo - Math Utility
export function calculateSum(numbers: number[]): number {
  return numbers.reduce((acc, curr) => acc + curr, 0);
}
`;
zip.addFile('src/clean.ts', Buffer.from(cleanTs, 'utf8'));

const outputPath = path.join(fixturesDir, 'sample-vulnerable-repo.zip');
zip.writeZip(outputPath);
console.log(`Successfully generated fixture: ${outputPath} (${fs.statSync(outputPath).size} bytes)`);
