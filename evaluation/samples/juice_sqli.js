// OWASP Juice Shop Login Handler (SQL Injection vulnerability)
const express = require('express');
const router = express.Router();
const db = require('../db');

router.post('/login', (req, res) => {
  const email = req.body.email || '';
  const password = req.body.password || '';

  // Vulnerable raw SQL concatenation allowing authentication bypass
  const query = "SELECT * FROM Users WHERE email = '" + email + "' AND password = '" + password + "' AND deletedAt IS NULL";
  
  db.query(query, (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database query failed' });
    }
    if (users.length > 0) {
      return res.status(200).json({ token: 'mock-jwt-token', user: users[0] });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  });
});

module.exports = router;
