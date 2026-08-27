const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const BASE_URL = 'http://localhost:3000/api';
const dbConfig = {
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'root',
  database: 'secureid_db'
};
const JWT_SECRET = process.env.JWT_SECRET;

async function testOidcOAuth() {
  console.log('--- Testing OAuth 2.0 / OpenID Connect Identity Provider ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  const ts = Date.now();
  const clientId = `client_suite_${ts}`;
  const clientSecret = `secret_suite_${ts}`;
  const clientName = `Suite Partner App ${ts}`;
  const redirectUri = `http://localhost:3000/suite_callback_${ts}`;

  // Register client
  await conn.execute(
    'INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uri, created_at) VALUES (?, ?, ?, ?, NOW())',
    [clientId, clientSecret, clientName, redirectUri]
  );
  assert(true, 'Registered test OAuth 2.0 Client Application in database');

  // Setup user & session
  const email = `oidc_user_${ts}@example.com`;
  const phone = `82${ts.toString().slice(-8)}`;
  const passwordHash = await bcrypt.hash('Password@123', 10);
  const [u] = await conn.execute(
    `INSERT INTO users (first_name, last_name, email, phone, password_hash, role, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
     VALUES ('OIDC', 'Tester', ?, ?, ?, 'admin', 1, 0, 0, NULL, NOW(), NOW())`,
    [email, phone, passwordHash]
  );
  const userId = u.insertId;
  const sessId = 'oidc_session_' + ts;
  await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR), NOW())', [sessId, userId]);

  // 1. Authorization Request without Session
  const rUnauth = await fetch(`${BASE_URL}/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`, { method: 'GET' });
  assert(rUnauth.status === 401, 'Authorization request without session cookie rejected');

  // 2. Authorization Request with Invalid client_id
  const rBadClient = await fetch(`${BASE_URL}/oauth/authorize?client_id=bad_id&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`, {
    method: 'GET',
    headers: { 'Cookie': `secureid_session=${sessId}` }
  });
  assert(rBadClient.status === 400, 'Authorization request with invalid client_id rejected');

  // 3. Authorization Request with Invalid redirect_uri
  const rBadUri = await fetch(`${BASE_URL}/oauth/authorize?client_id=${clientId}&redirect_uri=http://bad.com/cb&response_type=code`, {
    method: 'GET',
    headers: { 'Cookie': `secureid_session=${sessId}` }
  });
  assert(rBadUri.status === 400, 'Authorization request with invalid redirect_uri rejected');

  // 4. Valid Authorization Request
  const rAuth = await fetch(`${BASE_URL}/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`, {
    method: 'GET',
    headers: { 'Cookie': `secureid_session=${sessId}` }
  });
  const dAuth = await rAuth.json();
  const code = dAuth.code;
  assert(rAuth.status === 200 && code, 'Valid authorization request issued 10-minute Authorization Code');

  // 5. Token Exchange with Invalid client_secret
  const rBadSecret = await fetch(`${BASE_URL}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, client_id: clientId, client_secret: 'bad_sec', redirect_uri: redirectUri })
  });
  assert(rBadSecret.status === 401, 'Token exchange with invalid client_secret rejected');

  // 6. Valid Token Exchange
  const rToken = await fetch(`${BASE_URL}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri })
  });
  const dToken = await rToken.json();
  assert(rToken.status === 200 && dToken.access_token && dToken.id_token, 'Valid token exchange issued access_token and id_token');

  // 7. Verify OIDC ID Token Standard Claims (iss, aud, sub, iat, exp, name, email, role)
  const decodedIdToken = jwt.verify(dToken.id_token, JWT_SECRET);
  assert(decodedIdToken.iss === 'http://localhost:3000', 'id_token contains correct iss claim');
  assert(decodedIdToken.aud === clientId, 'id_token contains correct aud claim (client_id)');
  assert(decodedIdToken.sub === String(userId), 'id_token contains correct sub claim (user_id)');
  assert(typeof decodedIdToken.iat === 'number', 'id_token contains correct iat claim');
  assert(typeof decodedIdToken.exp === 'number' && decodedIdToken.exp > decodedIdToken.iat, 'id_token contains valid exp claim');
  assert(decodedIdToken.email === email && decodedIdToken.role === 'admin', 'id_token contains user identity & role claims');

  // 8. Test Single-Use Authorization Code Enforcement (Re-use rejected)
  const rReuse = await fetch(`${BASE_URL}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri })
  });
  assert(rReuse.status === 400, 'Re-using authorization code rejected (Single-use enforcement)');

  // 9. Test OIDC UserInfo Endpoint with Access Token
  const rUserinfo = await fetch(`${BASE_URL}/oauth/userinfo`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${dToken.access_token}` }
  });
  const dUserinfo = await rUserinfo.json();
  assert(rUserinfo.status === 200 && dUserinfo.sub === String(userId) && dUserinfo.email === email, 'GET /api/oauth/userinfo returned OIDC claims');

  await conn.end();
  return { passed, failed };
}

module.exports = testOidcOAuth;
if (require.main === module) {
  testOidcOAuth().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
