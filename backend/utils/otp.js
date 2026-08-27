const crypto = require('crypto');
const bcrypt = require('bcrypt');

/**
 * Generates a cryptographically secure 6-digit OTP code string.
 */
function generateOTP() {
  const otpNumber = crypto.randomInt(100000, 1000000);
  return otpNumber.toString();
}

/**
 * Hashes an OTP code string using bcrypt.
 * @param {string} otp 
 * @returns {Promise<string>} Hashed OTP string
 */
async function hashOTP(otp) {
  const saltRounds = 10;
  return await bcrypt.hash(otp, saltRounds);
}

module.exports = {
  generateOTP,
  hashOTP
};
