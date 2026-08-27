/**
 * Role-Based Access Control (RBAC) Middleware
 * @param {string} requiredRole - Role required to access the endpoint (e.g. 'admin')
 */
function requireRole(requiredRole) {
  return (req, res, next) => {
    // Inspect user role attached by authMiddleware or jwtMiddleware
    const userRole = req.user?.role || req.jwtUser?.role;

    if (!userRole) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Authentication required.'
      });
    }

    if (userRole !== requiredRole) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        message: 'Access denied. Administrator role required.'
      });
    }

    next();
  };
}

module.exports = requireRole;
