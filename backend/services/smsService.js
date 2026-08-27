/**
 * SMS Service Abstraction Module
 *
 * DEVELOPMENT / TESTING MODE:
 * - Uses MockSmsProvider which logs simulated OTP output for local testing.
 * - OTPs are NOT printed in production logs.
 *
 * PRODUCTION MODE CONFIGURATION REQUIRED:
 * - Configure RealSmsProvider (e.g. Twilio, AWS SNS, Infobip) in production environment.
 */

class MockSmsProvider {
  async sendSms({ to, message, otp, challengeId }) {
    if (process.env.NODE_ENV !== 'production') {
      console.log('\n========================================');
      console.log('[SIMULATED SMS PROVIDER - DEV MODE]');
      console.log(`To: ${to}`);
      console.log(`Message: ${message}`);
      if (otp) console.log(`OTP: ${otp}`);
      if (challengeId) console.log(`Challenge ID: ${challengeId}`);
      console.log('========================================\n');
    }
    return { success: true, provider: 'mock' };
  }
}

class RealSmsProvider {
  async sendSms({ to, message }) {
    // Production SMS Integration Placeholder (e.g. Twilio Client)
    // const twilio = require('twilio');
    // const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
    // await client.messages.create({ body: message, from: process.env.TWILIO_PHONE, to });
    throw new Error('Real SMS Provider not configured. Set TWILIO_SID / TWILIO_AUTH_TOKEN in production .env');
  }
}

const smsProvider = (process.env.NODE_ENV === 'production' && process.env.TWILIO_SID)
  ? new RealSmsProvider()
  : new MockSmsProvider();

/**
 * Sends SMS OTP to recipient.
 * @param {string} to - Recipient phone number
 * @param {string} otp - 6-digit OTP code
 * @param {string} [challengeId] - Associated challenge ID
 */
async function sendSmsOTP(to, otp, challengeId) {
  const message = `Your SecureID verification code is: ${otp}. Valid for 5 minutes.`;
  return await smsProvider.sendSms({ to, message, otp, challengeId });
}

module.exports = {
  sendSmsOTP,
  smsProvider
};
