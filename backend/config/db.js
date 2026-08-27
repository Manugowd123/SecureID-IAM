const mysql = require('mysql2/promise');
require('dotenv').config();

// In a traditional long-running server, one process holds one pool for the
// life of the process. In a serverless environment (e.g. Vercel), each warm
// function instance still only creates this pool once -- Node's module
// cache means this file's top-level code runs once per container, and the
// same `pool` object is reused across subsequent invocations on that warm
// instance -- but many concurrent cold-started instances can each open their
// own pool against the same external MySQL server at once. A small
// per-instance pool size (configurable via DB_CONNECTION_LIMIT, default 3)
// keeps total connection usage against the external database reasonable
// under serverless concurrency; raise it via env var for a traditional
// single-process deployment if desired.
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'secureid_db',
  waitForConnections: true,
  connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT || '3', 10),
  queueLimit: 0
});

async function testConnection() {
  try {
    const connection = await pool.getConnection();
    connection.release();
    return true;
  } catch (error) {
    console.error('MySQL connection error:', error.message);
    throw error;
  }
}

module.exports = {
  pool,
  testConnection
};
