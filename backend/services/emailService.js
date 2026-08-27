const nodemailer = require('nodemailer');
require('dotenv').config();

/**
 * Creates a Nodemailer transporter for Gmail SMTP using environment variables.
 */
function createTransporter() {
  const emailUser = (process.env.EMAIL_USER || '').trim();
  const rawPass = (process.env.EMAIL_APP_PASSWORD || '').trim();
  // Strip any spaces from Google 16-character App Passwords (e.g. "abcd efgh ijkl mnop" -> "abcdefghijklmnop")
  const cleanPass = rawPass.replace(/\s+/g, '');

  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: emailUser,
      pass: cleanPass
    }
  });
}

/**
 * Sends a real email verification OTP via Nodemailer Gmail SMTP.
 * @param {string} toEmail - Recipient email address
 * @param {string} otp - 6-digit verification code
 * @returns {Promise<boolean>}
 */
async function sendVerificationEmail(toEmail, otp) {
  const emailUser = (process.env.EMAIL_USER || '').trim();
  const emailPass = (process.env.EMAIL_APP_PASSWORD || '').trim();

  if (!emailUser || !emailPass) {
    throw new Error('EMAIL_USER or EMAIL_APP_PASSWORD is missing in backend .env file.');
  }

  const transporter = createTransporter();

  const mailOptions = {
    from: `"SecureID" <${emailUser}>`,
    to: toEmail,
    subject: 'SecureID Email Verification OTP',
    html: `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 12px; background-color: #ffffff; color: #1e293b;">
        <div style="text-align: center; margin-bottom: 24px;">
          <h1 style="color: #2563eb; font-size: 24px; font-weight: 700; margin: 0; letter-spacing: -0.5px;">SecureID</h1>
          <p style="color: #64748b; font-size: 14px; margin-top: 4px;">Identity & Access Management</p>
        </div>
        
        <p style="font-size: 15px; line-height: 1.5; color: #334155; margin-bottom: 16px;">Hello,</p>
        <p style="font-size: 15px; line-height: 1.5; color: #334155; margin-bottom: 20px;">
          Thank you for registering with <strong>SecureID</strong>. Use the verification code below to complete your email verification:
        </p>

        <div style="background: linear-gradient(135deg, #f8fafc 0%, #edf2f7 100%); border: 1px solid #cbd5e1; padding: 18px; text-align: center; border-radius: 8px; margin: 24px 0;">
          <span style="font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #1e293b; font-family: monospace;">${otp}</span>
        </div>

        <p style="font-size: 14px; color: #64748b; margin-bottom: 12px;">
          ⏰ This code will expire in <strong>5 minutes</strong>.
        </p>
        
        <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #f1f5f9;">
          <p style="font-size: 12px; color: #ef4444; margin: 0; line-height: 1.4;">
            <strong>Security Notice:</strong> Never share this OTP with anyone. SecureID employees will never ask for your verification code.
          </p>
        </div>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
  return true;
}

module.exports = {
  sendVerificationEmail
};
