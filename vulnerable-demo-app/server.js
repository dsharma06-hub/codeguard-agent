const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = new sqlite3.Database(':memory:');

// Hardcoded Production JWT Secret
const JWT_SECRET = 'super_secret_jwt_key_that_should_never_be_hardcoded_12345';
const HARDCODED_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJhZG1pbiI6dHJ1ZX0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';

// VULNERABILITY 1: SQL Injection via query concatenation
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Direct user-input concatenation into SQL query
  const sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (rows && rows.length > 0) {
      const token = jwt.sign({ user: rows[0].username, role: 'admin' }, JWT_SECRET);
      return res.json({ success: true, token });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  });
});

// VULNERABILITY 2: Cross-Site Scripting (XSS) via unescaped query reflection
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  
  // Unsanitized user parameter reflected directly into HTML response
  const html = `
    <!DOCTYPE html>
    <html>
      <head><title>Product Search</title></head>
      <body>
        <h1>Search Results</h1>
        <div id="results">You searched for: ${query}</div>
      </body>
    </html>
  `;
  
  res.send(html);
});

app.listen(3000, () => {
  console.log('Vulnerable demo server running on port 3000');
});
