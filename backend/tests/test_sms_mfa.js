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

async function testSmsMfa() {
  console.log('--- Testing Phone Verification & SMS MFA Setup ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `sms_mfa_${ts}@example.com`;
    const phone = `86${ts.toString().slice(-8)}`;

    // Create a new verified user via registration + manual verification
    const rReg = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'SMS',
        lastName: 'MFA',
        email: email,
        phone: phone,
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    const dReg = await rReg.json();
    const userId = dReg.userId;

    // Manually mark email verified so we can request SMS OTP
    await conn.execute('UPDATE users SET email_verified = 1 WHERE id = ?', [userId]);

    // 1. Request SMS OTP
    const rSend = await fetch(`${BASE_URL}/send-sms-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: userId })
    });
    const dSend = await rSend.json();
    const challengeId = dSend.challengeId;
    assert(rSend.status === 200 && challengeId, 'POST /api/send-sms-otp generated SMS challenge ID');

    // 2. Verify Wrong OTP is rejected
    const rWrong = await fetch(`${BASE_URL}/verify-sms-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: '000000' })
    });
    assert(rWrong.status === 400, 'Wrong SMS OTP rejected (HTTP 400)');

    // 3. Set a known OTP and verify success
    const testOtp = '654321';
    const otpHash = await bcrypt.hash(testOtp, 10);
    await conn.execute('UPDATE otp_challenges SET otp_hash = ? WHERE challenge_id = ?', [otpHash, challengeId]);

    const rSuccess = await fetch(`${BASE_URL}/verify-sms-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: testOtp })
    });
    const dSuccess = await rSuccess.json();
    assert(rSuccess.status === 200 && dSuccess.success && dSuccess.mfaEnabled, 'Correct SMS OTP enables SMS MFA (mfaEnabled = true)');

    // Verify mfa_enabled = 1 in database
    const [uRows] = await conn.execute('SELECT mfa_enabled FROM users WHERE id = ?', [userId]);
    assert(uRows[0].mfa_enabled === 1, 'MFA is enabled in user table (mfa_enabled = 1)');

    // 4. Test Single-Use (cannot reuse verified OTP challenge)
    const rReuse = await fetch(`${BASE_URL}/verify-sms-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: testOtp })
    });
    assert(rReuse.status === 400, 'Verified SMS OTP challenge cannot be reused');

    // 5. Changing the phone later resets MFA appropriately (via profile update)
    // To do this, we need a session cookie. Let's create a session.
    const sessId = 'test_sms_sess_' + ts;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())', [sessId, userId, expiresAt]);

    const newPhone = `87${ts.toString().slice(-8)}`;
    const rProfile = await fetch(`${BASE_URL}/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': `secureid_session=${sessId}`
      },
      body: JSON.stringify({
        firstName: 'SMS',
        lastName: 'MFA',
        phone: newPhone
      })
    });
    assert(rProfile.status === 200, 'Updating user phone number succeeded (HTTP 200)');

    // Verify database mfa_enabled has been reset to 0
    const [uRowsAfterUpdate] = await conn.execute('SELECT phone, mfa_enabled FROM users WHERE id = ?', [userId]);
    assert(uRowsAfterUpdate[0].phone === newPhone && uRowsAfterUpdate[0].mfa_enabled === 0, 'Changing the phone number resets mfa_enabled to 0');

  } catch (err) {
    console.error('SMS MFA Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testSmsMfa;
if (require.main === module) {
  testSmsMfa().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
