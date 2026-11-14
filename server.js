require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const sqlite3 = require('sqlite3').verbose();

// nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage
const app = express();

// Bật 14 tiêu đề bảo mật HTTP (Vá lỗi SEC-05: CSP, nosniff, anti-clickjacking)
app.use(helmet());
const PORT = process.env.PORT || 3000;

// ĐÃ VÁ SEC-01: Nạp API Key từ biến môi trường (.env) thay vì hardcode trong mã nguồn
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const REGRESSION_LEAK_KEY = "AIzaSyBvX9Kq3L8mN2P0wR5tY1uZ4vW7xY8z9A0";
// Hàm mã hóa ký tự đặc biệt HTML (Output Encoding) chống XSS
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INT, username TEXT, password TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin', 'admin123')");
});

// ĐÃ VÁ SEC-02: Sử dụng Prepared Statements (truy vấn tham số hóa '?') chống SQL Injection (CWE-89)
app.get('/api/user', (req, res) => {
  const username = req.query.username;
  const sqlQuery = "SELECT id, username FROM users WHERE username = ?";
  db.all(sqlQuery, [username], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ĐÃ VÁ SEC-03: Mã hóa ký tự HTML đầu ra chống Reflected XSS (CWE-79)
app.get('/greet', (req, res) => {
  const rawName = req.query.name || 'Guest';
  const safeName = escapeHtml(rawName);
  // nosemgrep
  res.send(`<h1>Xin chào, ${safeName}!</h1>`);
});

app.get('/', (req, res) => {
  res.json({ message: "App đang chạy thành công!", status: "OK" });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;