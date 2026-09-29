const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const useSsl = String(process.env.DATABASE_SSL).toLowerCase() === 'true';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function initDb() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
  await pool.query(sql);
}

async function q(text, params) { return pool.query(text, params); }
module.exports = { pool, q, initDb };
