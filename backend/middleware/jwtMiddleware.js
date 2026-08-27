const { verifyAccessToken } = require('../utils/jwt');

/**
 * JWT Verification Middleware
 * Validates Authorization: Bearer <accessToken> header only.
 */
function jwtMiddleware(req, res, next) {
  try {
    let token = null;
    const authHeader = req.headers.authorization;

    if (authHeader) {
      const parts = authHeader.split(' ');
      if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
        token = parts[1];
      }
    }

    if (!token || typeof token !== 'string') {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'JWT Access Token must be a valid string.'
      });
    }

    const decoded = verifyAccessToken(token);
    req.jwtUser = decoded;
    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        code: 'TOKEN_EXPIRED',
        message: 'JWT Access Token has expired.'
      });
    }

    return res.status(401).json({
      success: false,
      code: 'INVALID_TOKEN',
      message: 'Invalid JWT Access Token.'
    });
  }
}

module.exports = jwtMiddleware;
