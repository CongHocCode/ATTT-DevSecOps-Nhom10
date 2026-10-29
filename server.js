const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = process.env.PORT || 3000;

// SEC-01: Secret Leak (Gitleaks) - Lộ API Key cố định
const GOOGLE_API_KEY = "AIzaSyD-FAKE-KEY-999999999999999999";

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INT, username TEXT, password TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin', 'admin123')");
});

// SEC-02: SQL Injection (Semgrep - CWE-89)
app.get('/api/user', (req, res) => {
  const username = req.query.username;
  const sqlQuery = "SELECT id, username FROM users WHERE username = '" + username + "'";
  db.all(sqlQuery, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// SEC-03: Reflected XSS (Semgrep - CWE-79)
app.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  res.send(`<h1>Xin chào, ${name}!</h1>`);
});

app.get('/', (req, res) => {
  res.json({ message: "App đang chạy thành công!", status: "OK" });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;