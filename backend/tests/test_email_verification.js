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

async function testEmailVerification() {
  console.log('--- Testing Email Verification / Email OTP ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `email_verify_${ts}@example.com`;
    const phone = `85${ts.toString().slice(-8)}`;

    // Create a new unregistered user via registration
    const rReg = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Email',
        lastName: 'Verify',
        email: email,
        phone: phone,
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    const dReg = await rReg.json();
    const userId = dReg.userId;
    const challengeId = dReg.challengeId;

    // Verify raw user has email_verified = 0
    const [uRows] = await conn.execute('SELECT email_verified FROM users WHERE id = ?', [userId]);
    assert(uRows[0].email_verified === 0, 'New user is initially unverified (email_verified = 0)');

    // 1. Verify invalid challengeId rejected
    const rBadChal = await fetch(`${BASE_URL}/verify-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: 'bad-challenge-id', otp: '123456' })
    });
    assert(rBadChal.status === 404, 'Invalid challenge ID rejected with HTTP 404');

    // 2. Fetch the otp challenge from DB to verify structure & format
    const [challenges] = await conn.execute('SELECT * FROM otp_challenges WHERE challenge_id = ?', [challengeId]);
    assert(challenges.length === 1, 'OTP challenge recorded in database');
    const challenge = challenges[0];
    assert(challenge.channel === 'email' && challenge.purpose === 'registration_email', 'OTP challenge has correct channel and purpose');

    // 3. Test wrong OTP rejection
    const rWrongOtp = await fetch(`${BASE_URL}/verify-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: '000000' })
    });
    const dWrongOtp = await rWrongOtp.json();
    assert(rWrongOtp.status === 400 && dWrongOtp.code === 'INVALID_OTP', 'Incorrect OTP rejected with HTTP 400 and INVALID_OTP');

    // 4. Test expired OTP rejection
    await conn.execute('UPDATE otp_challenges SET expires_at = DATE_SUB(NOW(), INTERVAL 1 HOUR) WHERE id = ?', [challenge.id]);
    const rExpired = await fetch(`${BASE_URL}/verify-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: '123456' })
    });
    const dExpired = await rExpired.json();
    assert(rExpired.status === 400 && dExpired.code === 'OTP_EXPIRED', 'Expired OTP rejected with HTTP 400 and OTP_EXPIRED');

    // Restore expiration but set custom known OTP to verify success
    const testOtp = '112233';
    const otpHash = await bcrypt.hash(testOtp, 10);
    await conn.execute('UPDATE otp_challenges SET otp_hash = ?, expires_at = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE id = ?', [otpHash, challenge.id]);

    // 5. Verify email with correct OTP
    const rSuccess = await fetch(`${BASE_URL}/verify-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: testOtp })
    });
    const dSuccess = await rSuccess.json();
    assert(rSuccess.status === 200 && dSuccess.success, 'Correct OTP verifies email successfully (HTTP 200)');

    // Verify email_verified = 1 in database
    const [uRowsVerified] = await conn.execute('SELECT email_verified FROM users WHERE id = ?', [userId]);
    assert(uRowsVerified[0].email_verified === 1, 'Correct OTP updates user email_verified = 1');

    // 6. Test single-use (cannot reuse verified OTP challenge)
    const rReuse = await fetch(`${BASE_URL}/verify-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: testOtp })
    });
    const dReuse = await rReuse.json();
    assert(rReuse.status === 400 && dReuse.code === 'CHALLENGE_INACTIVE', 'Verified OTP challenge cannot be reused');

    // 7. Resend OTP creates a new challenge and invalidates the previous one
    const rResend = await fetch(`${BASE_URL}/send-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: userId })
    });
    // It should say already verified because email_verified = 1
    assert(rResend.status === 400 && (await rResend.json()).code === 'ALREADY_VERIFIED', 'Resend OTP fails for already verified users');

    // 8. OTP max-attempts enforcement: a fresh challenge locks out after 3 wrong attempts,
    //    and even the correct OTP is then rejected until a new challenge is requested.
    const email2 = `email_verify_attempts_${ts}@example.com`;
    const phone2 = `86${ts.toString().slice(-8)}`;
    const rReg2 = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Attempts',
        lastName: 'Test',
        email: email2,
        phone: phone2,
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    const dReg2 = await rReg2.json();
    const challengeId2 = dReg2.challengeId;

    const [challenges2] = await conn.execute('SELECT id, max_attempts FROM otp_challenges WHERE challenge_id = ?', [challengeId2]);
    const maxAttempts = challenges2[0].max_attempts;

    let lastAttemptStatus, lastAttemptBody;
    for (let i = 0; i < maxAttempts; i++) {
      const rAttempt = await fetch(`${BASE_URL}/verify-email-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId: challengeId2, otp: '999999' })
      });
      lastAttemptStatus = rAttempt.status;
      lastAttemptBody = await rAttempt.json();
    }
    assert(lastAttemptStatus === 400 && lastAttemptBody.code === 'MAX_ATTEMPTS',
      `Exhausting all ${maxAttempts} wrong OTP attempts locks the challenge (HTTP 400 MAX_ATTEMPTS)`);

    // Set the hash to a known value the attacker (correctly) can't use anymore, and confirm
    // even the *correct* OTP is now rejected because max_attempts was reached.
    const knownOtp = '654321';
    const knownHash = await bcrypt.hash(knownOtp, 10);
    await conn.execute('UPDATE otp_challenges SET otp_hash = ? WHERE id = ?', [knownHash, challenges2[0].id]);
    const rAfterLockout = await fetch(`${BASE_URL}/verify-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId2, otp: knownOtp })
    });
    const dAfterLockout = await rAfterLockout.json();
    assert(rAfterLockout.status === 400 && dAfterLockout.code === 'MAX_ATTEMPTS',
      'Correct OTP is still rejected once max attempts has been reached');

  } catch (err) {
    console.error('Email Verification Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testEmailVerification;
if (require.main === module) {
  testEmailVerification().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
