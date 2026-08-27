process.env.NODE_ENV = 'test';

const testRegistration = require('./test_registration');
const testEmailVerification = require('./test_email_verification');
const testSmsMfa = require('./test_sms_mfa');
const testLoginLockout = require('./test_login_lockout');
const testLoginMfa = require('./test_login_mfa');
const testSessions = require('./test_sessions');
const testPasswordReset = require('./test_password_reset');
const testOidcOAuth = require('./test_oidc_oauth');
const testSecurityHardening = require('./test_security_hardening');
const testIntegration = require('./test_integration');
const testApiToken = require('./test_api_token');
const testProtectedEndpoint = require('./test_protected_endpoint');

async function runMasterTestSuite() {
  console.log('================================================================');
  console.log('  SECUREID IAM SYSTEM - COMPREHENSIVE AUTOMATED TEST SUITE    ');
  console.log('================================================================\n');

  let totalPassed = 0;
  let totalFailed = 0;

  const suites = [
    { name: 'User Registration & Validation', fn: testRegistration },
    { name: 'Email Verification / Email OTP', fn: testEmailVerification },
    { name: 'Phone Verification & SMS MFA Setup', fn: testSmsMfa },
    { name: 'Password Authentication & Lockout', fn: testLoginLockout },
    { name: 'SMS Login MFA Challenge', fn: testLoginMfa },
    { name: 'Server-Side Session Management', fn: testSessions },
    { name: 'Password Reset & Single-Use Token Flow', fn: testPasswordReset },
    { name: 'OAuth 2.0 / OpenID Connect Identity Provider', fn: testOidcOAuth },
    { name: 'Security Hardening & Vulnerabilities', fn: testSecurityHardening },
    { name: 'API Token Issuance (POST /api/token) & Remember Me', fn: testApiToken },
    { name: 'Protected Resource Endpoint (GET /api/protected)', fn: testProtectedEndpoint },
    { name: 'End-to-End Integration Flow', fn: testIntegration }
  ];

  for (const suite of suites) {
    try {
      const res = await suite.fn();
      totalPassed += res.passed;
      totalFailed += res.failed;
    } catch (err) {
      console.error(`Suite Error [${suite.name}]:`, err);
      totalFailed++;
    }
    console.log('');
  }

  console.log('================================================================');
  console.log(`  FINAL SYSTEM TEST RESULTS: ${totalPassed} PASSED, ${totalFailed} FAILED  `);
  console.log('================================================================\n');

  if (totalFailed > 0) {
    process.exit(1);
  }
}

runMasterTestSuite();
