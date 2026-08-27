const mysql = require('mysql2/promise');

const BASE_URL = 'http://localhost:3000/api';
const dbConfig = {
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'root',
  database: 'secureid_db'
};

async function testRegistration() {
  console.log('--- Testing User Registration & Validation ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  try {
    const ts = Date.now();
    const email = `reg_user_${ts}@example.com`;
    const phone = `83${ts.toString().slice(-8)}`;

    // 1. Missing fields rejection
    const rMissing = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    assert(rMissing.status === 400, 'Registration with missing fields rejected (HTTP 400)');

    // 2. Invalid email format rejection
    const rBadEmail = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Bad',
        lastName: 'Email',
        email: 'invalid-email-format',
        phone: phone,
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    assert(rBadEmail.status === 400, 'Registration with invalid email format rejected (HTTP 400)');

    // 3. Invalid phone format rejection
    const rBadPhone = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Bad',
        lastName: 'Phone',
        email: email,
        phone: '12345',
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    assert(rBadPhone.status === 400, 'Registration with invalid phone format rejected (HTTP 400)');

    // 4. Weak password rejection
    const rWeakPw = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Weak',
        lastName: 'Pw',
        email: email,
        phone: phone,
        password: '123',
        confirmPassword: '123'
      })
    });
    assert(rWeakPw.status === 400, 'Registration with weak password rejected (HTTP 400)');

    // 5. Successful user registration
    const rReg = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Reg',
        lastName: 'User',
        email: email,
        phone: phone,
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    const dReg = await rReg.json();
    assert(rReg.status === 201 && dReg.success && dReg.userId, 'User registration succeeded (HTTP 201 Created)');

    // 6. Duplicate email rejection
    const rDupEmail = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Reg',
        lastName: 'User',
        email: email,
        phone: `84${ts.toString().slice(-8)}`,
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    assert(rDupEmail.status === 409, 'Duplicate email registration rejected (HTTP 409 Conflict)');

    // 7. Duplicate phone rejection
    const rDupPhone = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Reg',
        lastName: 'User',
        email: `another_${ts}@example.com`,
        phone: phone,
        password: 'Password@123',
        confirmPassword: 'Password@123'
      })
    });
    assert(rDupPhone.status === 409, 'Duplicate phone registration rejected (HTTP 409 Conflict)');

  } catch (err) {
    console.error('Registration Test Error:', err);
    failed++;
  }

  return { passed, failed };
}

module.exports = testRegistration;
if (require.main === module) {
  testRegistration().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
