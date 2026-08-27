const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

const BASE_URL = 'http://localhost:3000/api';
const dbConfig = {
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'root',
  database: 'secureid_db'
};

async function testLoginLockout() {
  console.log('--- Testing Password Authentication & Account Lockout ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `lock_user_${ts}@example.com`;
    const phone = `84${ts.toString().slice(-8)}`;
    const pwd = 'Password@123';
    const hash = await bcrypt.hash(pwd, 10);

    const [u] = await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('Lock', 'User', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
      [email, phone, hash]
    );
    const userId = u.insertId;

    // 1. Invalid email does not leak registration status
    const rNoUser = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `nonexistent_${ts}@example.com`, password: pwd })
    });
    const dNoUser = await rNoUser.json();
    assert(rNoUser.status === 401 && dNoUser.code === 'INVALID_CREDENTIALS', 'Login with non-existing email returns standard 401 INVALID_CREDENTIALS');

    // 2. Invalid password rejection
    const rBad = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'WrongPassword@123' })
    });
    assert(rBad.status === 401 && (await rBad.json()).code === 'INVALID_CREDENTIALS', 'Invalid password attempt rejected with 401 INVALID_CREDENTIALS');

    // 3. Failed attempt tracked in DB
    const [rowsAttempt1] = await conn.execute('SELECT failed_login_attempts FROM users WHERE id = ?', [userId]);
    assert(rowsAttempt1[0].failed_login_attempts === 1, 'Failed attempt tracked and incremented correctly in database');

    // 4. Perform 4 more failed attempts to trigger lock
    for (let i = 0; i < 4; i++) {
      await fetch(`${BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'WrongPassword@123' })
      });
    }

    // 5. Verify Account Locked (HTTP 423)
    const rLocked = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd })
    });
    const dLocked = await rLocked.json();
    assert(rLocked.status === 423 && dLocked.code === 'ACCOUNT_LOCKED', '5 consecutive failed logins trigger Account Lockout (HTTP 423)');

    // 6. Test Lock Expiration logic
    await conn.execute('UPDATE users SET account_locked_until = DATE_SUB(NOW(), INTERVAL 1 SECOND) WHERE id = ?', [userId]);
    const rLockExpired = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd })
    });
    assert(rLockExpired.status === 200 && (await rLockExpired.json()).success, 'Expired account lockout allows successful login');

    // 7. Success resets failed attempt counter
    const [rowsReset] = await conn.execute('SELECT failed_login_attempts, account_locked_until FROM users WHERE id = ?', [userId]);
    assert(rowsReset[0].failed_login_attempts === 0 && rowsReset[0].account_locked_until === null, 'Successful login resets failed attempts and lockout to defaults');

  } catch (err) {
    console.error('Login Lockout Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testLoginLockout;
if (require.main === module) {
  testLoginLockout().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
