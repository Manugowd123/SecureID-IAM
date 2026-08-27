const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { pool } = require('../config/db');
const { generateOTP, hashOTP } = require('../utils/otp');
const { sendVerificationEmail } = require('../services/emailService');
const { generateAccessToken, generateIdToken } = require('../utils/jwt');
const { logAuditEvent, getUserAuditLogs } = require('../services/auditService');
const { sendSmsOTP: sendSmsService } = require('../services/smsService');

/**
 * Creates a cryptographically secure 64-character session ID and stores it in sessions table.
 * @param {number} userId
 * @param {boolean} [rememberMe=false] - When true, extends session lifetime to 30 days (Remember Me).
 * @returns {Promise<{sessionId: string, expiresAt: Date}>}
 */
async function createServerSession(userId, rememberMe = false) {
  const sessionId = crypto.randomBytes(32).toString('hex'); // 64 hex characters
  const sessionLifetimeMs = rememberMe
    ? REMEMBER_ME_MAX_AGE_MS // 30 days
    : DEFAULT_SESSION_MAX_AGE_MS; // 24 hours
  const expiresAt = new Date(Date.now() + sessionLifetimeMs);

  await pool.execute(
    `INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())`,
    [sessionId, userId, expiresAt]
  );

  return { sessionId, expiresAt };
}

// Email regex pattern
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Phone regex pattern (accepts 10-15 digits, optional + prefix)
const PHONE_REGEX = /^\+?[0-9]{10,15}$/;

// Session Cookie Configuration
const COOKIE_NAME = 'secureid_session';
const DEFAULT_SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours (standard session)
const REMEMBER_ME_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days (Remember Me)

/**
 * Builds session cookie options, extending maxAge when Remember Me is requested.
 * @param {boolean} [rememberMe=false]
 * @returns {object} Express res.cookie() options
 */
function getCookieOptions(rememberMe = false) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: rememberMe ? REMEMBER_ME_MAX_AGE_MS : DEFAULT_SESSION_MAX_AGE_MS
  };
}

const CLEAR_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production'
};

/**
 * Validates password strength:
 * - At least 8 characters long
 * - Contains uppercase letter
 * - Contains lowercase letter
 * - Contains digit
 * - Contains special character
 */
function isPasswordStrong(password) {
  if (!password || password.length < 8) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  return hasUpper && hasLower && hasDigit && hasSpecial;
}

/**
 * Registration API Endpoint Handler
 * POST /api/register
 */
async function register(req, res) {
  try {
    const { firstName, lastName, email, phone, password, confirmPassword } = req.body || {};

    // 1. Backend Validations (Phase 3 & 16)
    if (!firstName || typeof firstName !== 'string' || !firstName.trim() || firstName.trim().length > 50) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_FIRST_NAME',
        message: 'First name is required (string up to 50 characters).'
      });
    }

    if (!lastName || typeof lastName !== 'string' || !lastName.trim() || lastName.trim().length > 50) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_LAST_NAME',
        message: 'Last name is required (string up to 50 characters).'
      });
    }

    if (!email || typeof email !== 'string' || !email.trim() || email.trim().length > 100 || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_EMAIL',
        message: 'A valid email address is required (up to 100 characters).'
      });
    }

    const cleanPhone = typeof phone === 'string' ? phone.trim() : '';
    if (!cleanPhone || cleanPhone.length > 15 || !PHONE_REGEX.test(cleanPhone)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PHONE',
        message: 'A valid phone number (10-15 digits) is required.'
      });
    }

    if (!password || typeof password !== 'string' || password.length > 72) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PASSWORD',
        message: 'Password is required (string up to 72 characters).'
      });
    }

    if (!isPasswordStrong(password)) {
      return res.status(400).json({
        success: false,
        code: 'WEAK_PASSWORD',
        message: 'Password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and special character.'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        code: 'PASSWORD_MISMATCH',
        message: 'Password and Confirm Password do not match.'
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanFirstName = firstName.trim();
    const cleanLastName = lastName.trim();

    // 2. Check for Existing Email or Phone
    const [existingUsers] = await pool.execute(
      'SELECT id, email, phone FROM users WHERE email = ? OR phone = ? LIMIT 1',
      [cleanEmail, cleanPhone]
    );

    if (existingUsers.length > 0) {
      const existing = existingUsers[0];
      if (existing.email === cleanEmail) {
        return res.status(409).json({
          success: false,
          code: 'DUPLICATE_EMAIL',
          message: 'Email address is already registered.'
        });
      }
      if (existing.phone === cleanPhone) {
        return res.status(409).json({
          success: false,
          code: 'DUPLICATE_PHONE',
          message: 'Phone number is already registered.'
        });
      }
    }

    // 3. Password Hashing
    const passwordHash = await bcrypt.hash(password, 10);

    // 4. Create User Record
    const [userResult] = await pool.execute(
      `INSERT INTO users (
        first_name,
        last_name,
        email,
        phone,
        password_hash,
        email_verified,
        mfa_enabled,
        failed_login_attempts,
        account_locked_until,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, 0, 0, 0, NULL, NOW(), NOW())`,
      [cleanFirstName, cleanLastName, cleanEmail, cleanPhone, passwordHash]
    );

    const userId = userResult.insertId;

    // 5. Generate Secure Email OTP Challenge
    const rawOTP = generateOTP();
    const otpHash = await hashOTP(rawOTP);
    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes expiry

    await pool.execute(
      `INSERT INTO otp_challenges (
        challenge_id,
        user_id,
        channel,
        purpose,
        otp_hash,
        expires_at,
        attempts,
        max_attempts,
        created_at
      ) VALUES (?, ?, 'email', 'registration_email', ?, ?, 0, 3, NOW())`,
      [challengeId, userId, otpHash, expiresAt]
    );

    // 6. Send Real Email Verification OTP via Nodemailer Gmail SMTP
    // Delivery is fire-and-forget: the OTP challenge already exists in the database
    // (and can be verified via /verify-email-otp) regardless of whether the outbound
    // email transport succeeds, so a slow/unreachable SMTP provider must not block
    // or fail the registration request itself.
    sendVerificationEmail(cleanEmail, rawOTP).catch((emailErr) => {
      console.error('Email Delivery Error:', emailErr.message || emailErr);
    });

    // 7. Success Response
    return res.status(201).json({
      success: true,
      message: 'Registration started. Email verification required.',
      userId: userId,
      challengeId: challengeId
    });

  } catch (error) {
    console.error('Registration Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred during registration. Please try again.'
    });
  }
}

/**
 * Verify Email OTP Endpoint Handler
 * POST /api/verify-email-otp
 */
async function verifyEmailOTP(req, res) {
  try {
    const { challengeId, otp } = req.body || {};

    if (!challengeId || !otp || !otp.trim()) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Challenge ID and OTP are required.'
      });
    }

    // Find challenge
    const [challenges] = await pool.execute(
      `SELECT id, user_id, purpose, otp_hash, attempts, max_attempts, expires_at, verified_at, invalidated_at 
       FROM otp_challenges WHERE challenge_id = ? LIMIT 1`,
      [challengeId]
    );

    if (challenges.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'INVALID_CHALLENGE',
        message: 'Invalid challenge ID.'
      });
    }

    const challenge = challenges[0];

    if (challenge.purpose !== 'registration_email') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PURPOSE',
        message: 'Invalid OTP challenge purpose.'
      });
    }

    if (challenge.verified_at || challenge.invalidated_at) {
      return res.status(400).json({
        success: false,
        code: 'CHALLENGE_INACTIVE',
        message: 'OTP challenge has already been used or invalidated.'
      });
    }

    // Check expiry
    if (new Date() > new Date(challenge.expires_at)) {
      return res.status(400).json({
        success: false,
        code: 'OTP_EXPIRED',
        message: 'OTP has expired. Please request a new OTP.'
      });
    }

    // Check max attempts prior to comparing
    if (challenge.attempts >= challenge.max_attempts) {
      return res.status(400).json({
        success: false,
        code: 'MAX_ATTEMPTS',
        message: 'Maximum OTP attempts reached. Please request a new OTP.'
      });
    }

    // Compare OTP
    const isMatch = await bcrypt.compare(otp.trim(), challenge.otp_hash);

    if (!isMatch) {
      const newAttempts = challenge.attempts + 1;
      await pool.execute(
        'UPDATE otp_challenges SET attempts = ? WHERE id = ?',
        [newAttempts, challenge.id]
      );

      if (newAttempts >= challenge.max_attempts) {
        return res.status(400).json({
          success: false,
          code: 'MAX_ATTEMPTS',
          message: 'Maximum OTP attempts reached. Please request a new OTP.'
        });
      }

      const attemptsRemaining = challenge.max_attempts - newAttempts;
      return res.status(400).json({
        success: false,
        code: 'INVALID_OTP',
        message: 'Incorrect OTP.',
        attemptsRemaining: attemptsRemaining
      });
    }

    // Mark challenge verified and update user email_verified = true
    await pool.execute(
      'UPDATE otp_challenges SET verified_at = NOW() WHERE id = ?',
      [challenge.id]
    );

    await pool.execute(
      'UPDATE users SET email_verified = 1, updated_at = NOW() WHERE id = ?',
      [challenge.user_id]
    );

    return res.status(200).json({
      success: true,
      message: 'Email verified successfully.',
      userId: challenge.user_id
    });

  } catch (error) {
    console.error('Verify Email OTP Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while verifying OTP.'
    });
  }
}

/**
 * Resend Email OTP Endpoint Handler
 * POST /api/send-email-otp
 */
async function sendEmailOTP(req, res) {
  try {
    const { userId } = req.body || {};

    if (!userId) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_USER_ID',
        message: 'User ID is required.'
      });
    }

    const [users] = await pool.execute(
      'SELECT id, email, email_verified FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'User not found.'
      });
    }

    const user = users[0];

    if (user.email_verified) {
      return res.status(400).json({
        success: false,
        code: 'ALREADY_VERIFIED',
        message: 'Email is already verified.'
      });
    }

    if (process.env.NODE_ENV !== 'test') {
      // Cooldown check (60 seconds)
      const [recentChallenges] = await pool.execute(
        `SELECT created_at FROM otp_challenges 
         WHERE user_id = ? AND purpose = 'registration_email' AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
         LIMIT 1`,
        [userId]
      );
      if (recentChallenges.length >= 2) {
        return res.status(429).json({
          success: false,
          code: 'COOLDOWN_ACTIVE',
          message: 'Please wait 60 seconds before requesting another verification code.'
        });
      }

      // Max resends check (5 resends per 15 minutes)
      const [historyChallenges] = await pool.execute(
        `SELECT count(*) as count FROM otp_challenges 
         WHERE user_id = ? AND purpose = 'registration_email' AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)`,
        [userId]
      );
      if (historyChallenges[0].count >= 5) {
        return res.status(429).json({
          success: false,
          code: 'TOO_MANY_REQUESTS',
          message: 'Maximum verification attempts exceeded. Please try again in 15 minutes.'
        });
      }
    }

    // Invalidate previous active email challenges
    await pool.execute(
      `UPDATE otp_challenges 
       SET invalidated_at = NOW() 
       WHERE user_id = ? AND purpose = 'registration_email' AND verified_at IS NULL AND invalidated_at IS NULL`,
      [userId]
    );

    // Create new challenge
    const rawOTP = generateOTP();
    const otpHash = await hashOTP(rawOTP);
    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await pool.execute(
      `INSERT INTO otp_challenges (
        challenge_id,
        user_id,
        channel,
        purpose,
        otp_hash,
        expires_at,
        attempts,
        max_attempts,
        created_at
      ) VALUES (?, ?, 'email', 'registration_email', ?, ?, 0, 3, NOW())`,
      [challengeId, userId, otpHash, expiresAt]
    );

    // Send Real Email Verification OTP via Nodemailer Gmail SMTP
    // Fire-and-forget for the same reason as initial registration (see register()):
    // the OTP challenge is already persisted, so transport delivery failures/latency
    // must not block or fail this request.
    sendVerificationEmail(user.email, rawOTP).catch((emailErr) => {
      console.error('Resend Email Delivery Error:', emailErr.message || emailErr);
    });

    return res.status(200).json({
      success: true,
      message: 'New email OTP sent.',
      challengeId: challengeId
    });

  } catch (error) {
    console.error('Send Email OTP Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while generating email OTP.'
    });
  }
}

/**
 * Send SMS OTP Endpoint Handler
 * POST /api/send-sms-otp
 */
async function sendSmsOTP(req, res) {
  try {
    const { userId } = req.body || {};

    if (!userId) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_USER_ID',
        message: 'User ID is required.'
      });
    }

    const [users] = await pool.execute(
      'SELECT id, phone, email_verified, mfa_enabled FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'User not found.'
      });
    }

    const user = users[0];

    if (!user.email_verified) {
      return res.status(400).json({
        success: false,
        code: 'EMAIL_NOT_VERIFIED',
        message: 'Email must be verified before SMS OTP can be sent.'
      });
    }

    if (user.mfa_enabled) {
      return res.status(400).json({
        success: false,
        code: 'MFA_ALREADY_ENABLED',
        message: 'MFA is already enabled for this account.'
      });
    }

    if (process.env.NODE_ENV !== 'test') {
      // Cooldown check (60 seconds)
      const [recentChallenges] = await pool.execute(
        `SELECT created_at FROM otp_challenges 
         WHERE user_id = ? AND purpose = 'registration_sms' AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
         LIMIT 1`,
        [userId]
      );
      if (recentChallenges.length >= 2) {
        return res.status(429).json({
          success: false,
          code: 'COOLDOWN_ACTIVE',
          message: 'Please wait 60 seconds before requesting another verification code.'
        });
      }

      // Max resends check (5 resends per 15 minutes)
      const [historyChallenges] = await pool.execute(
        `SELECT count(*) as count FROM otp_challenges 
         WHERE user_id = ? AND purpose = 'registration_sms' AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)`,
        [userId]
      );
      if (historyChallenges[0].count >= 5) {
        return res.status(429).json({
          success: false,
          code: 'TOO_MANY_REQUESTS',
          message: 'Maximum verification attempts exceeded. Please try again in 15 minutes.'
        });
      }
    }

    // Invalidate previous active SMS registration challenges
    await pool.execute(
      `UPDATE otp_challenges 
       SET invalidated_at = NOW() 
       WHERE user_id = ? AND purpose = 'registration_sms' AND verified_at IS NULL AND invalidated_at IS NULL`,
      [userId]
    );

    // Create new SMS challenge
    const rawOTP = generateOTP();
    const otpHash = await hashOTP(rawOTP);
    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await pool.execute(
      `INSERT INTO otp_challenges (
        challenge_id,
        user_id,
        channel,
        purpose,
        otp_hash,
        expires_at,
        attempts,
        max_attempts,
        created_at
      ) VALUES (?, ?, 'sms', 'registration_sms', ?, ?, 0, 3, NOW())`,
      [challengeId, userId, otpHash, expiresAt]
    );

    try {
      await sendSmsService(user.phone, rawOTP, challengeId);
    } catch (smsErr) {
      console.error('SMS Delivery Error:', smsErr.message || smsErr);
      return res.status(500).json({
        success: false,
        code: 'SMS_SEND_FAILED',
        message: 'Failed to send SMS OTP. Please try again.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'SMS OTP generated.',
      challengeId: challengeId
    });

  } catch (error) {
    console.error('Send SMS OTP Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while generating SMS OTP.'
    });
  }
}

/**
 * Verify SMS OTP Endpoint Handler
 * POST /api/verify-sms-otp
 */
async function verifySmsOTP(req, res) {
  try {
    const { challengeId, otp } = req.body || {};

    if (!challengeId || !otp || !otp.trim()) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Challenge ID and OTP are required.'
      });
    }

    const [challenges] = await pool.execute(
      `SELECT id, user_id, purpose, otp_hash, attempts, max_attempts, expires_at, verified_at, invalidated_at 
       FROM otp_challenges WHERE challenge_id = ? LIMIT 1`,
      [challengeId]
    );

    if (challenges.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'INVALID_CHALLENGE',
        message: 'Invalid challenge ID.'
      });
    }

    const challenge = challenges[0];

    if (challenge.purpose !== 'registration_sms') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PURPOSE',
        message: 'Invalid OTP challenge purpose.'
      });
    }

    if (challenge.verified_at || challenge.invalidated_at) {
      return res.status(400).json({
        success: false,
        code: 'CHALLENGE_INACTIVE',
        message: 'OTP challenge has already been used or invalidated.'
      });
    }

    if (new Date() > new Date(challenge.expires_at)) {
      return res.status(400).json({
        success: false,
        code: 'OTP_EXPIRED',
        message: 'OTP has expired. Please request a new OTP.'
      });
    }

    if (challenge.attempts >= challenge.max_attempts) {
      return res.status(400).json({
        success: false,
        code: 'MAX_ATTEMPTS',
        message: 'Maximum OTP attempts reached. Please request a new OTP.'
      });
    }

    const isMatch = await bcrypt.compare(otp.trim(), challenge.otp_hash);

    if (!isMatch) {
      const newAttempts = challenge.attempts + 1;
      await pool.execute(
        'UPDATE otp_challenges SET attempts = ? WHERE id = ?',
        [newAttempts, challenge.id]
      );

      if (newAttempts >= challenge.max_attempts) {
        return res.status(400).json({
          success: false,
          code: 'MAX_ATTEMPTS',
          message: 'Maximum OTP attempts reached. Please request a new OTP.'
        });
      }

      const attemptsRemaining = challenge.max_attempts - newAttempts;
      return res.status(400).json({
        success: false,
        code: 'INVALID_OTP',
        message: 'Incorrect OTP.',
        attemptsRemaining: attemptsRemaining
      });
    }

    // Mark challenge verified and update user mfa_enabled = true
    await pool.execute(
      'UPDATE otp_challenges SET verified_at = NOW() WHERE id = ?',
      [challenge.id]
    );

    await pool.execute(
      'UPDATE users SET mfa_enabled = 1, updated_at = NOW() WHERE id = ?',
      [challenge.user_id]
    );

    return res.status(200).json({
      success: true,
      message: 'MFA enabled successfully.',
      mfaEnabled: true
    });

  } catch (error) {
    console.error('Verify SMS OTP Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while verifying SMS OTP.'
    });
  }
}

/**
 * User Login Endpoint Handler
 * POST /api/login
 */
async function login(req, res) {
  try {
    const { email, password, rememberMe } = req.body || {};
    const wantsRememberMe = rememberMe === true || rememberMe === 'true';

    if (!email || !email.trim() || !password) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Email and password are required.'
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // 1. Query user by email
    const [users] = await pool.execute(
      `SELECT id, first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until 
       FROM users WHERE email = ? LIMIT 1`,
      [cleanEmail]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password.'
      });
    }

    const user = users[0];

    // 2. Check if account is locked
    if (user.account_locked_until) {
      const lockTime = new Date(user.account_locked_until);
      const now = new Date();
      if (now < lockTime) {
        const remainingMinutes = Math.ceil((lockTime - now) / (60 * 1000));
        return res.status(423).json({
          success: false,
          code: 'ACCOUNT_LOCKED',
          message: `Account is temporarily locked due to multiple failed login attempts. Please try again in ${remainingMinutes} minute(s).`
        });
      } else {
        // Lock expired, reset lock
        await pool.execute(
          'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?',
          [user.id]
        );
        user.failed_login_attempts = 0;
        user.account_locked_until = null;
      }
    }

    // 3. Verify Password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      const newFailedAttempts = user.failed_login_attempts + 1;

      if (newFailedAttempts >= 5) {
        // Lock account for 15 minutes
        const lockUntil = new Date(Date.now() + 15 * 60 * 1000);
        await pool.execute(
          'UPDATE users SET failed_login_attempts = 5, account_locked_until = ?, updated_at = NOW() WHERE id = ?',
          [lockUntil, user.id]
        );

        return res.status(423).json({
          success: false,
          code: 'ACCOUNT_LOCKED',
          message: 'Account locked due to 5 consecutive failed login attempts. Please try again in 15 minutes.'
        });
      } else {
        await pool.execute(
          'UPDATE users SET failed_login_attempts = ?, updated_at = NOW() WHERE id = ?',
          [newFailedAttempts, user.id]
        );

        logAuditEvent({
          userId: user.id,
          eventType: 'LOGIN_FAILED',
          eventDetails: `Invalid password provided. Attempt ${newFailedAttempts}/5`,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });

        return res.status(401).json({
          success: false,
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password.'
        });
      }
    }

    // 4. Password valid! Reset failed login attempts
    await pool.execute(
      'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, updated_at = NOW() WHERE id = ?',
      [user.id]
    );

    // 5. Check email_verified
    if (!user.email_verified) {
      return res.status(403).json({
        success: false,
        code: 'EMAIL_NOT_VERIFIED',
        message: 'Email verification is required before logging in.',
        userId: user.id
      });
    }

    // 6. Check mfa_enabled
    if (user.mfa_enabled) {
      // Invalidate previous active login challenges
      await pool.execute(
        `UPDATE otp_challenges 
         SET invalidated_at = NOW() 
         WHERE user_id = ? AND purpose = 'login' AND verified_at IS NULL AND invalidated_at IS NULL`,
        [user.id]
      );

      // Create new SMS Login Challenge
      const rawOTP = generateOTP();
      const otpHash = await hashOTP(rawOTP);
      const challengeId = uuidv4();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

      await pool.execute(
        `INSERT INTO otp_challenges (
          challenge_id,
          user_id,
          channel,
          purpose,
          otp_hash,
          expires_at,
          attempts,
          max_attempts,
          created_at
        ) VALUES (?, ?, 'sms', 'login', ?, ?, 0, 3, NOW())`,
        [challengeId, user.id, otpHash, expiresAt]
      );

      try {
        await sendSmsService(user.phone, rawOTP, challengeId);
      } catch (smsErr) {
        console.error('SMS Delivery Error in login:', smsErr.message || smsErr);
        return res.status(500).json({
          success: false,
          code: 'SMS_SEND_FAILED',
          message: 'Failed to send SMS OTP. Please try again.'
        });
      }

      logAuditEvent({
        userId: user.id,
        eventType: 'LOGIN_STEP1_SUCCESS',
        eventDetails: 'Password verified. SMS MFA challenge issued.',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      return res.status(200).json({
        success: true,
        mfaRequired: true,
        message: 'Password authenticated. SMS MFA verification required.',
        userId: user.id,
        challengeId: challengeId,
        rememberMe: wantsRememberMe
      });
    }

    // MFA not enabled -> Create Session, Set Cookie, Generate JWT & Complete Login
    const { sessionId } = await createServerSession(user.id, wantsRememberMe);
    res.cookie(COOKIE_NAME, sessionId, getCookieOptions(wantsRememberMe));
    const accessToken = generateAccessToken(user);

    logAuditEvent({
      userId: user.id,
      eventType: 'LOGIN_SUCCESS',
      eventDetails: 'Direct password authentication successful (No MFA).',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    return res.status(200).json({
      success: true,
      mfaRequired: false,
      message: 'Login successful.',
      userId: user.id,
      sessionId: sessionId,
      accessToken: accessToken,
      rememberMe: wantsRememberMe,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred during login. Please try again.'
    });
  }
}

/**
 * Verify Login SMS OTP Endpoint Handler
 * POST /api/verify-login-otp
 */
async function verifyLoginOTP(req, res) {
  try {
    const { challengeId, otp, rememberMe } = req.body || {};
    const wantsRememberMe = rememberMe === true || rememberMe === 'true';

    if (!challengeId || !otp || !otp.trim()) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Challenge ID and OTP are required.'
      });
    }

    const [challenges] = await pool.execute(
      `SELECT id, user_id, purpose, otp_hash, attempts, max_attempts, expires_at, verified_at, invalidated_at 
       FROM otp_challenges WHERE challenge_id = ? LIMIT 1`,
      [challengeId]
    );

    if (challenges.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'INVALID_CHALLENGE',
        message: 'Invalid challenge ID.'
      });
    }

    const challenge = challenges[0];

    if (challenge.purpose !== 'login') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PURPOSE',
        message: 'Invalid OTP challenge purpose.'
      });
    }

    if (challenge.verified_at || challenge.invalidated_at) {
      return res.status(400).json({
        success: false,
        code: 'CHALLENGE_INACTIVE',
        message: 'OTP challenge has already been used or invalidated.'
      });
    }

    if (new Date() > new Date(challenge.expires_at)) {
      return res.status(400).json({
        success: false,
        code: 'OTP_EXPIRED',
        message: 'OTP has expired. Please request a new OTP.'
      });
    }

    if (challenge.attempts >= challenge.max_attempts) {
      return res.status(400).json({
        success: false,
        code: 'MAX_ATTEMPTS',
        message: 'Maximum OTP attempts reached. Please request a new OTP.'
      });
    }

    const isMatch = await bcrypt.compare(otp.trim(), challenge.otp_hash);

    if (!isMatch) {
      const newAttempts = challenge.attempts + 1;
      await pool.execute(
        'UPDATE otp_challenges SET attempts = ? WHERE id = ?',
        [newAttempts, challenge.id]
      );

      if (newAttempts >= challenge.max_attempts) {
        return res.status(400).json({
          success: false,
          code: 'MAX_ATTEMPTS',
          message: 'Maximum OTP attempts reached. Please request a new OTP.'
        });
      }

      const attemptsRemaining = challenge.max_attempts - newAttempts;
      return res.status(400).json({
        success: false,
        code: 'INVALID_OTP',
        message: 'Incorrect OTP.',
        attemptsRemaining: attemptsRemaining
      });
    }

    // Mark challenge verified
    await pool.execute(
      'UPDATE otp_challenges SET verified_at = NOW() WHERE id = ?',
      [challenge.id]
    );

    // Get User Details for return payload
    const [users] = await pool.execute(
      'SELECT id, first_name, last_name, email, phone FROM users WHERE id = ? LIMIT 1',
      [challenge.user_id]
    );

    const user = users[0];

    // Create server session upon successful MFA verification (30 days if Remember Me was requested,
    // 24 hours otherwise), set HttpOnly cookie & generate JWT
    const { sessionId } = await createServerSession(challenge.user_id, wantsRememberMe);
    res.cookie(COOKIE_NAME, sessionId, getCookieOptions(wantsRememberMe));
    const accessToken = generateAccessToken(user);

    logAuditEvent({
      userId: challenge.user_id,
      eventType: 'MFA_VERIFIED',
      eventDetails: 'SMS MFA challenge verified successfully.',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    logAuditEvent({
      userId: challenge.user_id,
      eventType: 'LOGIN_SUCCESS',
      eventDetails: 'MFA Login completed successfully.',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    return res.status(200).json({
      success: true,
      message: 'MFA Login verified successfully.',
      userId: challenge.user_id,
      sessionId: sessionId,
      accessToken: accessToken,
      rememberMe: wantsRememberMe,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('Verify Login OTP Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while verifying login OTP.'
    });
  }
}

/**
 * Resend Login SMS OTP Handler
 * POST /api/send-login-sms-otp
 */
async function sendLoginSmsOTP(req, res) {
  try {
    const { userId } = req.body || {};

    if (!userId) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_USER_ID',
        message: 'User ID is required.'
      });
    }

    const [users] = await pool.execute(
      'SELECT id, phone, email_verified, mfa_enabled FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'User not found.'
      });
    }

    const user = users[0];

    if (!user.email_verified || !user.mfa_enabled) {
      return res.status(400).json({
        success: false,
        code: 'MFA_NOT_ENABLED',
        message: 'MFA is not enabled for this user.'
      });
    }

    // Verify that the user has a recent login challenge (entered correct password recently) (Phase 5 & 6)
    const [activeLoginChallenges] = await pool.execute(
      `SELECT id FROM otp_challenges 
       WHERE user_id = ? AND purpose = 'login' AND verified_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
       LIMIT 1`,
      [userId, new Date(Date.now() - 5 * 60 * 1000)]
    );

    if (activeLoginChallenges.length === 0) {
      return res.status(400).json({
        success: false,
        code: 'NO_ACTIVE_LOGIN_SESSION',
        message: 'No active login session. Please enter password first.'
      });
    }

    if (process.env.NODE_ENV !== 'test') {
      // Cooldown check (60 seconds)
      const [recentChallenges] = await pool.execute(
        `SELECT created_at FROM otp_challenges 
         WHERE user_id = ? AND purpose = 'login' AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
         ORDER BY created_at ASC
         LIMIT 2`,
        [userId]
      );
      if (recentChallenges.length >= 2) {
        return res.status(429).json({
          success: false,
          code: 'COOLDOWN_ACTIVE',
          message: 'Please wait 60 seconds before requesting another login verification code.'
        });
      }

      // Max resends check (5 resends per 15 minutes)
      const [historyChallenges] = await pool.execute(
        `SELECT count(*) as count FROM otp_challenges 
         WHERE user_id = ? AND purpose = 'login' AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)`,
        [userId]
      );
      if (historyChallenges[0].count >= 5) {
        return res.status(429).json({
          success: false,
          code: 'TOO_MANY_REQUESTS',
          message: 'Maximum verification attempts exceeded. Please try again in 15 minutes.'
        });
      }
    }

    // Invalidate active login challenges
    await pool.execute(
      `UPDATE otp_challenges 
       SET invalidated_at = NOW() 
       WHERE user_id = ? AND purpose = 'login' AND verified_at IS NULL AND invalidated_at IS NULL`,
      [userId]
    );

    const rawOTP = generateOTP();
    const otpHash = await hashOTP(rawOTP);
    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await pool.execute(
      `INSERT INTO otp_challenges (
        challenge_id,
        user_id,
        channel,
        purpose,
        otp_hash,
        expires_at,
        attempts,
        max_attempts,
        created_at
      ) VALUES (?, ?, 'sms', 'login', ?, ?, 0, 3, NOW())`,
      [challengeId, userId, otpHash, expiresAt]
    );

    try {
      await sendSmsService(user.phone, rawOTP, challengeId);
    } catch (smsErr) {
      console.error('SMS Delivery Error in sendLoginSmsOTP:', smsErr.message || smsErr);
      return res.status(500).json({
        success: false,
        code: 'SMS_SEND_FAILED',
        message: 'Failed to send SMS OTP. Please try again.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'New login SMS OTP sent.',
      challengeId: challengeId
    });

  } catch (error) {
    console.error('Send Login SMS OTP Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while generating login SMS OTP.'
    });
  }
}

/**
 * Logout Endpoint Handler
 * POST /api/logout
 * Marks the active session as revoked (revoked_at = NOW()) in MySQL sessions table.
 */
async function logout(req, res) {
  try {
    let sessionId = req.cookies?.[COOKIE_NAME] || req.body?.sessionId;

    if (!sessionId && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
        sessionId = parts[1];
      }
    }

    console.log(`[LOGOUT] Request received. Session ID: ${sessionId || 'NONE'}`);

    if (!sessionId || typeof sessionId !== 'string') {
      res.clearCookie(COOKIE_NAME, CLEAR_COOKIE_OPTIONS);
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Session ID is required for logout.'
      });
    }

    const cleanSessionId = sessionId.trim();

    const [result] = await pool.execute(
      `UPDATE sessions SET revoked_at = NOW() WHERE session_id = ? AND revoked_at IS NULL`,
      [cleanSessionId]
    );

    console.log(`[LOGOUT] DB Update affectedRows: ${result.affectedRows}`);

    // Clear authentication cookie
    res.clearCookie(COOKIE_NAME, CLEAR_COOKIE_OPTIONS);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        code: 'SESSION_NOT_FOUND',
        message: 'Session was not found or was already revoked.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Logout successful.'
    });

  } catch (error) {
    console.error('[LOGOUT] Error during logout:', error);
    res.clearCookie(COOKIE_NAME, CLEAR_COOKIE_OPTIONS);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred during logout.'
    });
  }
}

/**
 * Protected User Profile Endpoint Handler
 * GET /api/me
 * Uses authMiddleware to return authenticated user profile.
 */
function getMe(req, res) {
  return res.status(200).json({
    success: true,
    user: req.user
  });
}

/**
 * Protected JWT Verification Endpoint Handler
 * POST /api/verify-token
 * Uses jwtMiddleware to return decoded JWT payload.
 */
function verifyToken(req, res) {
  return res.status(200).json({
    success: true,
    user: req.jwtUser
  });
}

/**
 * API Token Issuance Endpoint Handler
 * POST /api/token
 * Requires an authenticated server-side session (authMiddleware). Exchanges the
 * active session for a freshly-signed short-lived JWT Access Token that API
 * clients can use as a Bearer token against JWT-protected endpoints (e.g. GET /api/protected).
 */
async function issueApiToken(req, res) {
  try {
    // req.user is populated by authMiddleware from the validated session
    const accessToken = generateAccessToken({
      id: req.user.id,
      email: req.user.email,
      first_name: req.user.firstName,
      last_name: req.user.lastName,
      role: req.user.role
    });

    logAuditEvent({
      userId: req.user.id,
      eventType: 'API_TOKEN_ISSUED',
      eventDetails: 'JWT API access token issued for authenticated session.',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    return res.status(200).json({
      success: true,
      message: 'API access token issued successfully.',
      accessToken: accessToken,
      tokenType: 'Bearer',
      expiresIn: process.env.JWT_EXPIRES_IN || '15m'
    });

  } catch (error) {
    console.error('Issue API Token Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while issuing the API token.'
    });
  }
}

/**
 * Protected Resource Endpoint Handler
 * GET /api/protected
 * Demonstrates a backend resource guarded by jwtMiddleware. Requires a valid
 * Bearer JWT Access Token (obtainable via POST /api/token or the login flow).
 */
function protectedResource(req, res) {
  return res.status(200).json({
    success: true,
    message: 'Access granted to protected resource.',
    data: {
      resource: 'protected-data',
      accessedAt: new Date().toISOString()
    },
    user: req.jwtUser
  });
}

/**
 * Forgot Password Request Handler
 * POST /api/forgot-password
 */
async function forgotPassword(req, res) {
  try {
    const { email } = req.body || {};

    if (!email || !email.trim()) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Email address is required.'
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    if (!EMAIL_REGEX.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_EMAIL',
        message: 'Please provide a valid email address.'
      });
    }

    const [users] = await pool.execute(
      'SELECT id, first_name, email, phone, email_verified FROM users WHERE email = ? LIMIT 1',
      [cleanEmail]
    );

    const fakeChallengeId = uuidv4();

    if (users.length === 0) {
      // Prevent user/email enumeration: return generic success (Phase 9)
      return res.status(200).json({
        success: true,
        message: 'If the email address exists in our system, a password reset link/OTP has been sent.',
        challengeId: fakeChallengeId
      });
    }

    const user = users[0];

    if (!user.email_verified) {
      // Prevent email status verification enumeration: return generic success (Phase 9)
      return res.status(200).json({
        success: true,
        message: 'If the email address exists in our system, a password reset link/OTP has been sent.',
        challengeId: fakeChallengeId
      });
    }

    // Invalidate previous active email challenges
    await pool.execute(
      `UPDATE otp_challenges 
       SET invalidated_at = NOW() 
       WHERE user_id = ? AND channel = 'email' AND verified_at IS NULL AND invalidated_at IS NULL`,
      [user.id]
    );

    const rawOTP = generateOTP();
    const otpHash = await hashOTP(rawOTP);
    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await pool.execute(
      `INSERT INTO otp_challenges (
        challenge_id,
        user_id,
        channel,
        purpose,
        otp_hash,
        expires_at,
        attempts,
        max_attempts,
        created_at
      ) VALUES (?, ?, 'email', 'password_reset', ?, ?, 0, 3, NOW())`,
      [challengeId, user.id, otpHash, expiresAt]
    );

    // Fire-and-forget for the same reason as registration's OTP email (see register()):
    // the OTP challenge is already persisted, so transport delivery latency/failure
    // must not block this response (also avoids leaking user existence via response timing).
    sendVerificationEmail(cleanEmail, rawOTP).catch((emailErr) => {
      console.warn('[FORGOT PASSWORD] Email send attempt failed, logged simulated output:', emailErr.message || emailErr);
    });

    console.log('\n========================================');
    console.log('[PASSWORD RESET OTP]');
    console.log(`To: ${cleanEmail}`);
    console.log(`OTP: ${rawOTP}`);
    console.log(`Challenge ID: ${challengeId}`);
    console.log('========================================\n');

    return res.status(200).json({
      success: true,
      message: 'If the email address exists in our system, a password reset link/OTP has been sent.',
      challengeId: challengeId
    });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while generating password reset request.'
    });
  }
}

/**
 * Verify Password Reset OTP Handler
 * POST /api/verify-reset-otp
 */
async function verifyResetOTP(req, res) {
  try {
    const { challengeId, otp } = req.body || {};

    if (!challengeId || !otp || !otp.trim()) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Challenge ID and OTP are required.'
      });
    }

    const [challenges] = await pool.execute(
      `SELECT id, user_id, purpose, otp_hash, attempts, max_attempts, expires_at, verified_at, invalidated_at 
       FROM otp_challenges WHERE challenge_id = ? LIMIT 1`,
      [challengeId]
    );

    if (challenges.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'INVALID_CHALLENGE',
        message: 'Invalid challenge ID.'
      });
    }

    const challenge = challenges[0];

    if (challenge.purpose !== 'password_reset') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PURPOSE',
        message: 'Invalid OTP challenge purpose.'
      });
    }

    if (challenge.verified_at || challenge.invalidated_at) {
      return res.status(400).json({
        success: false,
        code: 'CHALLENGE_INACTIVE',
        message: 'OTP challenge has already been used or invalidated.'
      });
    }

    if (new Date() > new Date(challenge.expires_at)) {
      return res.status(400).json({
        success: false,
        code: 'OTP_EXPIRED',
        message: 'OTP has expired. Please request a new OTP.'
      });
    }

    if (challenge.attempts >= challenge.max_attempts) {
      return res.status(400).json({
        success: false,
        code: 'MAX_ATTEMPTS',
        message: 'Maximum OTP attempts reached. Please request a new OTP.'
      });
    }

    const isMatch = await bcrypt.compare(otp.trim(), challenge.otp_hash);

    if (!isMatch) {
      const newAttempts = challenge.attempts + 1;
      await pool.execute(
        'UPDATE otp_challenges SET attempts = ? WHERE id = ?',
        [newAttempts, challenge.id]
      );

      if (newAttempts >= challenge.max_attempts) {
        return res.status(400).json({
          success: false,
          code: 'MAX_ATTEMPTS',
          message: 'Maximum OTP attempts reached. Please request a new OTP.'
        });
      }

      const attemptsRemaining = challenge.max_attempts - newAttempts;
      return res.status(400).json({
        success: false,
        code: 'INVALID_OTP',
        message: 'Incorrect OTP.',
        attemptsRemaining: attemptsRemaining
      });
    }

    // Mark challenge verified and issue single-use 10-minute resetToken
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.execute(
      `UPDATE otp_challenges 
       SET verified_at = NOW(), reset_token = ?, reset_token_expires_at = ? 
       WHERE id = ?`,
      [resetToken, tokenExpiresAt, challenge.id]
    );

    return res.status(200).json({
      success: true,
      message: 'OTP verified successfully. Use the resetToken to set your new password.',
      resetToken: resetToken
    });

  } catch (error) {
    console.error('Verify Reset OTP Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while verifying reset OTP.'
    });
  }
}

/**
 * Reset Password Handler
 * POST /api/reset-password
 */
async function resetPassword(req, res) {
  try {
    const { resetToken, challengeId, otp, newPassword, confirmPassword } = req.body || {};

    if (!newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'New password and confirmation are required.'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        code: 'PASSWORD_MISMATCH',
        message: 'Passwords do not match.'
      });
    }

    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({
        success: false,
        code: 'WEAK_PASSWORD',
        message: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.'
      });
    }

    let targetUserId = null;

    // Path A: Authenticated by single-use resetToken
    if (resetToken) {
      const [tokens] = await pool.execute(
        `SELECT id, user_id, verified_at, reset_token_expires_at, reset_token_used_at 
         FROM otp_challenges WHERE reset_token = ? LIMIT 1`,
        [resetToken.trim()]
      );

      if (tokens.length === 0) {
        return res.status(404).json({
          success: false,
          code: 'INVALID_RESET_TOKEN',
          message: 'Invalid password reset token.'
        });
      }

      const tokenRecord = tokens[0];

      if (tokenRecord.reset_token_used_at !== null) {
        return res.status(400).json({
          success: false,
          code: 'RESET_TOKEN_ALREADY_USED',
          message: 'Password reset token has already been used.'
        });
      }

      if (new Date() > new Date(tokenRecord.reset_token_expires_at)) {
        return res.status(400).json({
          success: false,
          code: 'RESET_TOKEN_EXPIRED',
          message: 'Password reset token has expired.'
        });
      }

      // Single-use enforcement: mark used_at
      await pool.execute(
        'UPDATE otp_challenges SET reset_token_used_at = NOW() WHERE id = ?',
        [tokenRecord.id]
      );

      targetUserId = tokenRecord.user_id;

    } else if (challengeId) {
      // Path B: Direct challengeId + OTP verification
      const [challenges] = await pool.execute(
        `SELECT id, user_id, purpose, otp_hash, attempts, max_attempts, expires_at, verified_at, reset_token_used_at 
         FROM otp_challenges WHERE challenge_id = ? LIMIT 1`,
        [challengeId]
      );

      if (challenges.length === 0) {
        return res.status(404).json({
          success: false,
          code: 'INVALID_CHALLENGE',
          message: 'Invalid challenge ID.'
        });
      }

      const challenge = challenges[0];

      if (challenge.reset_token_used_at !== null) {
        return res.status(400).json({
          success: false,
          code: 'RESET_TOKEN_ALREADY_USED',
          message: 'Password reset challenge has already been used.'
        });
      }

      if (new Date() > new Date(challenge.expires_at)) {
        return res.status(400).json({
          success: false,
          code: 'OTP_EXPIRED',
          message: 'OTP has expired.'
        });
      }

      if (!challenge.verified_at) {
        if (!otp) {
          return res.status(400).json({
            success: false,
            code: 'OTP_REQUIRED',
            message: 'OTP verification required before resetting password.'
          });
        }

        const isMatch = await bcrypt.compare(otp.trim(), challenge.otp_hash);
        if (!isMatch) {
          return res.status(400).json({
            success: false,
            code: 'INVALID_OTP',
            message: 'Incorrect OTP.'
          });
        }
      }

      // Mark single-use
      await pool.execute(
        'UPDATE otp_challenges SET verified_at = NOW(), reset_token_used_at = NOW() WHERE id = ?',
        [challenge.id]
      );

      targetUserId = challenge.user_id;

    } else {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Valid password reset token or OTP challenge required.'
      });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    // Update user password and clear lockout counters
    await pool.execute(
      `UPDATE users 
       SET password_hash = ?, failed_login_attempts = 0, account_locked_until = NULL, updated_at = NOW() 
       WHERE id = ?`,
      [newPasswordHash, targetUserId]
    );

    // Revoke all active sessions for security
    await pool.execute(
      `UPDATE sessions SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL`,
      [targetUserId]
    );

    logAuditEvent({
      userId: targetUserId,
      eventType: 'PASSWORD_RESET_COMPLETED',
      eventDetails: 'User password reset completed successfully.',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    return res.status(200).json({
      success: true,
      message: 'Password reset successful. Please log in with your new password.'
    });

  } catch (error) {
    console.error('Reset Password Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while resetting password.'
    });
  }
}

/**
 * Update Authenticated User Profile Handler
 * PUT /api/profile
 */
async function updateProfile(req, res) {
  try {
    const { firstName, lastName, phone } = req.body || {};

    if (!firstName || !firstName.trim() || !lastName || !lastName.trim() || !phone || !phone.trim()) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'First name, last name, and phone number are required.'
      });
    }

    const cleanFirstName = firstName.trim();
    const cleanLastName = lastName.trim();
    const cleanPhone = phone.trim();

    if (!PHONE_REGEX.test(cleanPhone)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PHONE',
        message: 'Please provide a valid phone number (10-15 digits).'
      });
    }

    // Query current user details
    const [users] = await pool.execute(
      'SELECT id, phone, mfa_enabled FROM users WHERE id = ? LIMIT 1',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'User account not found.'
      });
    }

    const currentUser = users[0];

    // If phone number is updated, reset mfa_enabled to 0 for security
    const phoneChanged = currentUser.phone !== cleanPhone;
    const newMfaEnabled = phoneChanged ? 0 : currentUser.mfa_enabled;

    await pool.execute(
      `UPDATE users 
       SET first_name = ?, last_name = ?, phone = ?, mfa_enabled = ?, updated_at = NOW() 
       WHERE id = ?`,
      [cleanFirstName, cleanLastName, cleanPhone, newMfaEnabled, req.user.id]
    );

    return res.status(200).json({
      success: true,
      message: phoneChanged 
        ? 'Profile updated. Phone number changed, please re-verify SMS MFA.' 
        : 'Profile updated successfully.',
      user: {
        id: req.user.id,
        firstName: cleanFirstName,
        lastName: cleanLastName,
        email: req.user.email,
        phone: cleanPhone,
        mfaEnabled: Boolean(newMfaEnabled)
      }
    });

  } catch (error) {
    console.error('Update Profile Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while updating profile.'
    });
  }
}

/**
 * Authenticated Change Password Handler
 * POST /api/change-password
 */
async function changePassword(req, res) {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body || {};

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Current password, new password, and confirmation are required.'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        code: 'PASSWORD_MISMATCH',
        message: 'New passwords do not match.'
      });
    }

    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({
        success: false,
        code: 'WEAK_PASSWORD',
        message: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.'
      });
    }

    const [users] = await pool.execute(
      'SELECT id, password_hash FROM users WHERE id = ? LIMIT 1',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'User account not found.'
      });
    }

    const user = users[0];

    // Verify current password
    const isCurrentValid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isCurrentValid) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'Current password is incorrect.'
      });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    // Update user password
    await pool.execute(
      `UPDATE users 
       SET password_hash = ?, failed_login_attempts = 0, account_locked_until = NULL, updated_at = NOW() 
       WHERE id = ?`,
      [newPasswordHash, req.user.id]
    );

    // Revoke other active sessions for security
    const activeSessionId = req.session?.sessionId;
    if (activeSessionId) {
      await pool.execute(
        `UPDATE sessions SET revoked_at = NOW() WHERE user_id = ? AND session_id != ? AND revoked_at IS NULL`,
        [req.user.id, activeSessionId]
      );
    }

    return res.status(200).json({
      success: true,
      message: 'Password changed successfully.'
    });

  } catch (error) {
    console.error('Change Password Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while changing password.'
    });
  }
}

/**
 * Get Active Sessions Handler
 * GET /api/sessions
 */
async function getSessions(req, res) {
  try {
    const [rows] = await pool.execute(
      `SELECT id, session_id, expires_at, created_at 
       FROM sessions 
       WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW() 
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    const activeSessions = rows.map(row => ({
      id: row.id,
      sessionIdMasked: row.session_id.substring(0, 8) + '...' + row.session_id.substring(56),
      sessionId: row.session_id,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      isCurrentSession: row.session_id === req.session?.sessionId
    }));

    return res.status(200).json({
      success: true,
      count: activeSessions.length,
      sessions: activeSessions
    });

  } catch (error) {
    console.error('Get Sessions Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while retrieving active sessions.'
    });
  }
}

/**
 * Revoke Specific Session Handler
 * POST /api/sessions/revoke
 */
async function revokeSession(req, res) {
  try {
    const { targetSessionId } = req.body || {};

    if (!targetSessionId || typeof targetSessionId !== 'string') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Target session ID is required.'
      });
    }

    const cleanSessionId = targetSessionId.trim();

    const [result] = await pool.execute(
      `UPDATE sessions 
       SET revoked_at = NOW() 
       WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL`,
      [cleanSessionId, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        code: 'SESSION_NOT_FOUND',
        message: 'Session not found or already revoked.'
      });
    }

    // If revoking current active session, clear cookie
    if (cleanSessionId === req.session?.sessionId) {
      res.clearCookie(COOKIE_NAME, CLEAR_COOKIE_OPTIONS);
    }

    return res.status(200).json({
      success: true,
      message: 'Session revoked successfully.'
    });

  } catch (error) {
    console.error('Revoke Session Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while revoking session.'
    });
  }
}

/**
 * Revoke All Other Sessions Handler
 * POST /api/sessions/revoke-others
 */
async function revokeOtherSessions(req, res) {
  try {
    const currentSessionId = req.session?.sessionId;

    if (!currentSessionId) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Current session ID is missing.'
      });
    }

    const [result] = await pool.execute(
      `UPDATE sessions 
       SET revoked_at = NOW() 
       WHERE user_id = ? AND session_id != ? AND revoked_at IS NULL`,
      [req.user.id, currentSessionId]
    );

    return res.status(200).json({
      success: true,
      message: `Successfully revoked ${result.affectedRows} other active session(s).`
    });

  } catch (error) {
    console.error('Revoke Other Sessions Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while revoking other sessions.'
    });
  }
}

/**
 * Get Audit Logs Handler
 * GET /api/audit-logs
 */
async function getAuditLogs(req, res) {
  try {
    const logs = await getUserAuditLogs(req.user.id);
    return res.status(200).json({
      success: true,
      count: logs.length,
      logs: logs
    });
  } catch (error) {
    console.error('Get Audit Logs Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while retrieving audit logs.'
    });
  }
}

/**
 * Admin Get All Users Handler
 * GET /api/admin/users
 */
async function getAdminUsers(req, res) {
  try {
    const [rows] = await pool.execute(
      `SELECT id, first_name, last_name, email, phone, role, email_verified, mfa_enabled, 
              failed_login_attempts, account_locked_until, created_at 
       FROM users 
       ORDER BY id DESC`
    );

    const userList = rows.map(u => ({
      id: u.id,
      firstName: u.first_name,
      lastName: u.last_name,
      email: u.email,
      phone: u.phone,
      role: u.role,
      emailVerified: Boolean(u.email_verified),
      mfaEnabled: Boolean(u.mfa_enabled),
      failedAttempts: u.failed_login_attempts,
      isLocked: u.account_locked_until !== null && new Date(u.account_locked_until) > new Date(),
      createdAt: u.created_at
    }));

    return res.status(200).json({
      success: true,
      count: userList.length,
      users: userList
    });

  } catch (error) {
    console.error('Get Admin Users Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while retrieving user list.'
    });
  }
}

/**
 * Admin Toggle User Lock Handler
 * POST /api/admin/users/:userId/lock
 */
async function toggleUserLock(req, res) {
  try {
    const targetUserId = parseInt(req.params.userId, 10);
    const { lock } = req.body || {};

    if (!targetUserId || isNaN(targetUserId)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'Valid Target User ID is required.'
      });
    }

    const [users] = await pool.execute('SELECT id, role, account_locked_until FROM users WHERE id = ? LIMIT 1', [targetUserId]);
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'Target user not found.'
      });
    }

    const user = users[0];
    const shouldLock = lock !== undefined ? Boolean(lock) : (user.account_locked_until === null || new Date(user.account_locked_until) <= new Date());

    if (shouldLock) {
      // Lock user account and revoke sessions
      const lockUntil = new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000); // 100 years
      await pool.execute(
        'UPDATE users SET account_locked_until = ?, updated_at = NOW() WHERE id = ?',
        [lockUntil, targetUserId]
      );
      await pool.execute(
        'UPDATE sessions SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
        [targetUserId]
      );

      logAuditEvent({
        userId: req.user.id,
        eventType: 'ADMIN_USER_LOCKED',
        eventDetails: `Admin locked user account ID ${targetUserId}`,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      return res.status(200).json({
        success: true,
        isLocked: true,
        message: `User account ID ${targetUserId} locked successfully.`
      });

    } else {
      // Unlock user account
      await pool.execute(
        'UPDATE users SET account_locked_until = NULL, failed_login_attempts = 0, updated_at = NOW() WHERE id = ?',
        [targetUserId]
      );

      logAuditEvent({
        userId: req.user.id,
        eventType: 'ADMIN_USER_UNLOCKED',
        eventDetails: `Admin unlocked user account ID ${targetUserId}`,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      return res.status(200).json({
        success: true,
        isLocked: false,
        message: `User account ID ${targetUserId} unlocked successfully.`
      });
    }

  } catch (error) {
    console.error('Toggle User Lock Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while updating user lock status.'
    });
  }
}

/**
 * OAuth 2.0 / OIDC Authorization Code Issuer Endpoint Handler
 * GET /api/oauth/authorize
 */
async function oauthAuthorize(req, res) {
  try {
    const clientId = req.query.client_id || req.body.client_id;
    const redirectUri = req.query.redirect_uri || req.body.redirect_uri;
    const responseType = req.query.response_type || req.body.response_type || 'code';
    const scope = req.query.scope || req.body.scope || 'openid profile email';

    if (!clientId || !redirectUri) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REQUEST',
        message: 'client_id and redirect_uri parameters are required.'
      });
    }

    if (responseType !== 'code') {
      return res.status(400).json({
        success: false,
        code: 'UNSUPPORTED_RESPONSE_TYPE',
        message: 'Only response_type=code (Authorization Code Flow) is supported.'
      });
    }

    const [clients] = await pool.execute(
      'SELECT client_id, client_name, redirect_uri FROM oauth_clients WHERE client_id = ? LIMIT 1',
      [clientId]
    );

    if (clients.length === 0) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_CLIENT',
        message: 'Invalid or unregistered OAuth client_id.'
      });
    }

    const client = clients[0];

    if (client.redirect_uri !== redirectUri) {
      return res.status(400).json({
        success: false,
        code: 'REDIRECT_URI_MISMATCH',
        message: 'redirect_uri does not match client registration.'
      });
    }

    // Generate single-use authorization code (expires in 10 minutes)
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.execute(
      `INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [code, clientId, req.user.id, redirectUri, scope, expiresAt]
    );

    logAuditEvent({
      userId: req.user.id,
      eventType: 'OAUTH_AUTHORIZE_SUCCESS',
      eventDetails: `OAuth code issued for client ${client.client_name}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    const state = req.query.state || req.body.state;
    let finalRedirectUri = `${redirectUri}?code=${code}`;
    if (state && typeof state === 'string') {
      finalRedirectUri += `&state=${encodeURIComponent(state)}`;
    }

    return res.status(200).json({
      success: true,
      code: code,
      redirectUri: finalRedirectUri,
      clientName: client.client_name,
      scope: scope
    });

  } catch (error) {
    console.error('OAuth Authorize Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred during OAuth authorization.'
    });
  }
}

/**
 * OAuth 2.0 / OIDC Token Exchange Endpoint Handler
 * POST /api/oauth/token
 */
async function oauthToken(req, res) {
  try {
    const { grant_type, code, client_id, client_secret, redirect_uri } = req.body || {};

    if (grant_type !== 'authorization_code') {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only grant_type=authorization_code is supported.'
      });
    }

    if (!code || !client_id || !client_secret) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'code, client_id, and client_secret parameters are required.'
      });
    }

    // Verify client credentials
    const [clients] = await pool.execute(
      'SELECT client_id, client_secret, client_name, redirect_uri FROM oauth_clients WHERE client_id = ? LIMIT 1',
      [client_id]
    );

    if (clients.length === 0 || clients[0].client_secret !== client_secret) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication failed (invalid client_secret).'
      });
    }

    const client = clients[0];

    // Verify authorization code
    const [codes] = await pool.execute(
      'SELECT code, client_id, user_id, redirect_uri, scope, expires_at, used_at FROM oauth_codes WHERE code = ? AND client_id = ? LIMIT 1',
      [code, client_id]
    );

    if (codes.length === 0) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid authorization code.'
      });
    }

    const oauthCode = codes[0];

    if (oauthCode.used_at !== null) {
      return res.status(400).json({
        error: 'invalid_grant',
        code: 'CODE_ALREADY_USED',
        error_description: 'Authorization code has already been used.'
      });
    }

    if (new Date() > new Date(oauthCode.expires_at)) {
      return res.status(400).json({
        error: 'invalid_grant',
        code: 'CODE_EXPIRED',
        error_description: 'Authorization code has expired.'
      });
    }

    // Verify redirect_uri matches original authorization request (Phase 13)
    if (redirect_uri && oauthCode.redirect_uri !== redirect_uri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'redirect_uri does not match original authorization request.'
      });
    }

    // Mark code as used immediately (single-use enforcement via atomic update to prevent race conditions) (Phase 13)
    const [updateResult] = await pool.execute(
      'UPDATE oauth_codes SET used_at = NOW() WHERE code = ? AND used_at IS NULL',
      [code]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code has already been used.'
      });
    }

    // Query user details for token claims
    const [users] = await pool.execute(
      'SELECT id, first_name, last_name, email, phone, role FROM users WHERE id = ? LIMIT 1',
      [oauthCode.user_id]
    );

    if (users.length === 0) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'User associated with code not found.'
      });
    }

    const user = users[0];

    // Issue OAuth 2.0 Access Token and OpenID Connect ID Token
    const accessToken = generateAccessToken(user);
    const idToken = generateIdToken(user, client_id);

    logAuditEvent({
      userId: user.id,
      eventType: 'OAUTH_TOKEN_ISSUED',
      eventDetails: `OAuth access_token issued for client ${client.client_name}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    return res.status(200).json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      id_token: idToken,
      scope: oauthCode.scope || 'openid profile email'
    });

  } catch (error) {
    console.error('OAuth Token Error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred during OAuth token exchange.'
    });
  }
}

/**
 * OpenID Connect Standard UserInfo Endpoint Handler
 * GET /api/oauth/userinfo
 */
async function oauthUserInfo(req, res) {
  try {
    const userId = req.jwtUser?.userId;

    const [users] = await pool.execute(
      'SELECT id, first_name, last_name, email, phone, role, email_verified FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        error: 'user_not_found',
        error_description: 'User profile not found.'
      });
    }

    const user = users[0];

    return res.status(200).json({
      sub: String(user.id),
      name: `${user.first_name} ${user.last_name}`,
      given_name: user.first_name,
      family_name: user.last_name,
      email: user.email,
      email_verified: Boolean(user.email_verified),
      phone_number: user.phone,
      role: user.role
    });

  } catch (error) {
    console.error('OAuth UserInfo Error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred while retrieving userinfo.'
    });
  }
}

module.exports = {
  register,
  verifyEmailOTP,
  sendEmailOTP,
  sendSmsOTP,
  verifySmsOTP,
  login,
  verifyLoginOTP,
  sendLoginSmsOTP,
  logout,
  getMe,
  verifyToken,
  issueApiToken,
  protectedResource,
  forgotPassword,
  verifyResetOTP,
  resetPassword,
  updateProfile,
  changePassword,
  getSessions,
  revokeSession,
  revokeOtherSessions,
  getAuditLogs,
  getAdminUsers,
  toggleUserLock,
  oauthAuthorize,
  oauthToken,
  oauthUserInfo
};


