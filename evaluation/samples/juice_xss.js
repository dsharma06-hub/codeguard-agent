// OWASP Juice Shop Search / Track Order Result (Reflected XSS vulnerability)
const express = require('express');
const app = express();

app.get('/track-result', (req, res) => {
  const query = req.query.q || '';

  // Vulnerable reflected XSS: unescaped user input rendered directly in HTML
  const html = `
    <html>
      <body>
        <h1>Search Results</h1>
        <div id="results">No orders found matching: ${query}</div>
      </body>
    </html>
  `;

  res.send(html);
});

module.exports = app;
