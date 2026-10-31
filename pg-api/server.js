const express = require('express');
const { Pool } = require('pg');

// ===== CẤU HÌNH =====
const pool = new Pool({
  host: 'localhost', port: 5432,
  user: 'postgres', password: 'admin123',
  database: 'smart_lock',
});

const API_KEY  = '9f3a1c7e5b2d8a40c6e1f7b39d2a5c84e0b6173fa2d9c5e8';
const SCHEMA   = 'public';
const MAX_ROWS = 20000;     // tối đa số dòng mỗi bảng trả về
const EXCLUDE  = [];        // bảng KHÔNG cho đồng bộ, ví dụ: ['password_resets']
// =====================

pool.on('error', e => console.error('Lỗi pool:', e.message));

const app = express();

// Danh sách bảng thật trong schema (dùng làm whitelist, tránh SQL injection)
async function listTables() {
  const r = await pool.query(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = $1 AND table_type = 'BASE TABLE'
     ORDER BY table_name`, [SCHEMA]);
  return r.rows.map(x => x.table_name).filter(n => !EXCLUDE.includes(n));
}

const q = id => '"' + String(id).replace(/"/g, '""') + '"';

app.get('/', (req, res) => res.send('pg-api OK'));

// Mọi route /api đều phải có key đúng
app.use('/api', (req, res, next) => {
  if (req.query.key !== API_KEY) return res.status(401).json({ error: 'unauthorized' });
  next();
});

// ---- Route đặc biệt (đặt TRƯỚC /api/:name) ----

// Kiểm tra đang kết nối đúng DB nào
app.get('/api/_whoami', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT current_database() AS db, current_user AS usr, inet_server_port() AS port');
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Danh sách bảng + cột (Apps Script dùng để tự dò bảng)
app.get('/api/_tables', async (req, res) => {
  try {
    const names = await listTables();
    const r = await pool.query(
      `SELECT table_name, column_name, data_type
       FROM information_schema.columns
       WHERE table_schema = $1
       ORDER BY table_name, ordinal_position`, [SCHEMA]);
    const cols = {};
    r.rows.forEach(c => (cols[c.table_name] ||= []).push(c.column_name));
    res.json({ tables: names.map(n => ({ name: n, columns: cols[n] || [] })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Xem cấu trúc để đọc bằng mắt
app.get('/api/_schema', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT table_name, column_name, data_type
       FROM information_schema.columns
       WHERE table_schema = $1
       ORDER BY table_name, ordinal_position`, [SCHEMA]);
    const out = {};
    r.rows.forEach(c => (out[c.table_name] ||= []).push(c.column_name + ' (' + c.data_type + ')'));
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- Lấy dữ liệu 1 bảng ----
app.get('/api/:name', async (req, res) => {
  try {
    const names = await listTables();
    if (!names.includes(req.params.name)) return res.status(404).json({ error: 'not found' });
    const sql = `SELECT * FROM ${q(SCHEMA)}.${q(req.params.name)} ORDER BY 1 LIMIT ${MAX_ROWS}`;
    const r = await pool.query(sql);
    res.json({ fields: r.fields.map(f => f.name), rows: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(3000, () => console.log('API chạy ở port 3000'));