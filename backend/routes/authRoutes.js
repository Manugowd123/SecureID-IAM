const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const jwtMiddleware = require('../middleware/jwtMiddleware');
const requireRole = require('../middleware/rbacMiddleware');
const rateLimiter = require('../middleware/rateLimiter');

// Define rate limiters for authentication endpoints
const authLimiter = rateLimiter({
  windowMs: 60 * 1000,
  max: 300, // Safe default for testing and standard use
  message: 'Too many authentication attempts. Please try again later.'
});

// Public Registration Routes
router.post('/register', authLimiter, authController.register);
router.post('/verify-email-otp', authLimiter, authController.verifyEmailOTP);
router.post('/send-email-otp', authLimiter, authController.sendEmailOTP);
router.post('/send-sms-otp', authLimiter, authController.sendSmsOTP);
router.post('/verify-sms-otp', authLimiter, authController.verifySmsOTP);

// Public Login Routes
router.post('/login', authLimiter, authController.login);
router.post('/verify-login-otp', authLimiter, authController.verifyLoginOTP);
router.post('/send-login-sms-otp', authLimiter, authController.sendLoginSmsOTP);

// Self-Service Password Reset Routes
router.post('/forgot-password', authLimiter, authController.forgotPassword);
router.post('/verify-reset-otp', authLimiter, authController.verifyResetOTP);
router.post('/reset-password', authLimiter, authController.resetPassword);

// Session Logout Route
router.post('/logout', authController.logout);

// Protected Session User & Profile Endpoints
router.get('/me', authMiddleware, authController.getMe);
router.put('/profile', authMiddleware, authController.updateProfile);
router.post('/change-password', authMiddleware, authController.changePassword);

// Protected Active Sessions Management Endpoints
router.get('/sessions', authMiddleware, authController.getSessions);
router.post('/sessions/revoke', authMiddleware, authController.revokeSession);
router.post('/sessions/revoke-others', authMiddleware, authController.revokeOtherSessions);

// Protected Audit Logs Endpoint
router.get('/audit-logs', authMiddleware, authController.getAuditLogs);

// Protected Admin Governance & RBAC Endpoints
router.get('/admin/users', authMiddleware, requireRole('admin'), authController.getAdminUsers);
router.post('/admin/users/:userId/lock', authMiddleware, requireRole('admin'), authController.toggleUserLock);

// OAuth 2.0 / OpenID Connect (OIDC) Endpoints
router.get('/oauth/authorize', authMiddleware, authController.oauthAuthorize);
router.post('/oauth/token', authLimiter, authController.oauthToken);
router.get('/oauth/userinfo', jwtMiddleware, authController.oauthUserInfo);

// Protected JWT Verification Endpoint
router.post('/verify-token', jwtMiddleware, authController.verifyToken);

// API Token Issuance Endpoint (session -> JWT access token exchange)
router.post('/token', authLimiter, authMiddleware, authController.issueApiToken);

// Protected Resource Endpoint (guarded by JWT Bearer token)
router.get('/protected', jwtMiddleware, authController.protectedResource);

module.exports = router;
