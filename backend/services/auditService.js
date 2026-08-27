const { pool } = require('../config/db');

/**
 * Log an IAM Security Audit Event asynchronously.
 * @param {object} event - Audit Event object
 * @param {number|null} event.userId - User ID associated with event
 * @param {string} event.eventType - Standard event type identifier (e.g. LOGIN_SUCCESS, MFA_VERIFIED)
 * @param {string} [event.eventDetails] - Additional human readable details
 * @param {string} [event.ipAddress] - Request IP address
 * @param {string} [event.userAgent] - Request User Agent
 */
async function logAuditEvent({ userId = null, eventType, eventDetails = '', ipAddress = '', userAgent = '' }) {
  try {
    if (!eventType) return;

    const cleanType = String(eventType).trim().toUpperCase();
    const cleanDetails = eventDetails ? String(eventDetails).substring(0, 255) : null;
    const cleanIp = ipAddress ? String(ipAddress).substring(0, 45) : null;
    const cleanUa = userAgent ? String(userAgent).substring(0, 255) : null;

    await pool.execute(
      `INSERT INTO audit_logs (user_id, event_type, event_details, ip_address, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [userId, cleanType, cleanDetails, cleanIp, cleanUa]
    );

  } catch (error) {
    console.error('[AUDIT SERVICE] Failed to record audit log:', error.message || error);
  }
}

/**
 * Retrieve Audit Logs for a specific user.
 * @param {number} userId - User ID
 * @param {number} [limit=50] - Result limit
 * @returns {Promise<Array>} Audit Log entries
 */
async function getUserAuditLogs(userId, limit = 50) {
  const maxLimit = Math.min(parseInt(limit, 10) || 50, 100);
  const [rows] = await pool.execute(
    `SELECT id, event_type, event_details, ip_address, user_agent, created_at 
     FROM audit_logs 
     WHERE user_id = ? 
     ORDER BY created_at DESC 
     LIMIT ?`,
    [userId, maxLimit]
  );
  return rows;
}

module.exports = {
  logAuditEvent,
  getUserAuditLogs
};
