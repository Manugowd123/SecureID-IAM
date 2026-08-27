const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const BASE_URL = 'http://localhost:3000/api';
const dbConfig = { host: 'localhost', port: 3306, user: 'root', password: 'root', database: 'secureid_db' };

(async () => {
  const conn = await mysql.createConnection(dbConfig);
  const ts = Date.now();
  const email = `dbg_login_mfa_${ts}@example.com`;
  const phone = `87${ts.toString().slice(-8)}`;
  const pwd = 'Password@123';
  const hash = await bcrypt.hash(pwd, 10);
  const [u] = await conn.execute(
    `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
     VALUES ('Login', 'MFA', ?, ?, ?, 1, 1, 0, NULL, NOW(), NOW())`,
    [email, phone, hash]
  );
  const userId = u.insertId;
  console.log('userId', userId);

  const rStep1 = await fetch(`${BASE_URL}/login`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ email, password: pwd }) });
  const dStep1 = await rStep1.json();
  console.log('step1', rStep1.status, dStep1);

  const rWrong = await fetch(`${BASE_URL}/verify-login-otp`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ challengeId: dStep1.challengeId, otp: '000000' }) });
  console.log('wrong otp status', rWrong.status, await rWrong.json());

  const rResend = await fetch(`${BASE_URL}/send-login-sms-otp`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ userId }) });
  console.log('resend status', rResend.status, await rResend.json());

  await conn.end();
})();
