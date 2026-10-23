const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');

// VULNERABILITY: SQL Injection in user lookup helper
function findUserByEmail(email, callback) {
  // Unsanitized raw query interpolation
  const query = "SELECT id, email, role FROM users WHERE email = '" + email + "' AND status = 'active'";
  db.all(query, callback);
}

// VULNERABILITY: SQL Injection in product filter
function getProductsByCategory(category, minPrice) {
  return new Promise((resolve, reject) => {
    const sql = `SELECT * FROM products WHERE category = '${category}' AND price >= ${minPrice}`;
    db.all(sql, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

module.exports = { findUserByEmail, getProductsByCategory };
