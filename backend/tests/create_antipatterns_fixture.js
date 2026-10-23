import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import AdmZip from 'adm-zip';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fixturesDir = path.join(__dirname, 'fixtures');
fs.mkdirSync(fixturesDir, { recursive: true });

const zip = new AdmZip();

// 1. Sensitive routes with no rate limiting (Express)
const authJs = `const express = require('express');
const router = express.Router();

// Sensitive authentication endpoint without rate limiting
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    res.json({ token: 'jwt-session-token' });
});

// Sensitive registration endpoint without rate limiting
router.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    res.json({ id: 101, username });
});

// Sensitive password reset endpoint without rate limiting
router.post('/reset-password', (req, res) => {
    const { email } = req.body;
    res.json({ message: 'Password reset link sent' });
});

module.exports = router;
`;
zip.addFile('src/routes/auth.js', Buffer.from(authJs, 'utf8'));

// 2. Express App setup without rate-limiting middleware
const appJs = `const express = require('express');
const authRoutes = require('./routes/auth');

const app = express();
app.use(express.json());

// Routes mounted without global or route-level rate limiting
app.use('/auth', authRoutes);

app.listen(3000, () => {
    console.log('App running on port 3000');
});

module.exports = app;
`;
zip.addFile('src/app.js', Buffer.from(appJs, 'utf8'));

// 3. Hardcoded production URLs in client service
const clientTs = `import axios from 'axios';

// Hardcoded production endpoint in fetch() call
export async function fetchUserData() {
    const response = await fetch("https://api.mycompany.com/v1/users");
    return response.json();
}

// Hardcoded production endpoint in axios.post() call
export async function processPayment(paymentDetails: any) {
    const response = await axios.post("https://production.codeguard.io/api/checkout", paymentDetails);
    return response.data;
}

// Hardcoded production endpoint in axios config object
export async function fetchTelemetry() {
    return await axios({
        method: 'get',
        url: "https://backend.prod.codeguard.io/metrics"
    });
}
`;
zip.addFile('src/services/apiClient.ts', Buffer.from(clientTs, 'utf8'));

// 4. package.json without rate-limiting dependencies
const packageJson = JSON.stringify(
  {
    name: "ai-antipatterns-sample",
    version: "1.0.0",
    description: "Sample project demonstrating AI-generated code antipatterns for CodeGuard testing",
    dependencies: {
      "express": "^4.21.2",
      "axios": "^1.7.0"
    }
  },
  null,
  2
);
zip.addFile('package.json', Buffer.from(packageJson, 'utf8'));

const outputPath = path.join(fixturesDir, 'ai-antipatterns-sample.zip');
zip.writeZip(outputPath);

console.log(`Successfully generated fixture: ${outputPath} (${fs.statSync(outputPath).size} bytes)`);
