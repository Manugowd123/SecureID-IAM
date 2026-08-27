document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');

  // In-memory registration session storage
  window.registrationSession = {
    userId: null,
    challengeId: null
  };

  function showAlert(message, type = 'error') {
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
  }

  function hideAlert() {
    alertBox.style.display = 'none';
    alertBox.textContent = '';
  }

  function showStep(stepId) {
    hideAlert();
    document.querySelectorAll('.step-panel').forEach(panel => {
      panel.classList.remove('active');
    });
    const target = document.getElementById(stepId);
    if (target) {
      target.classList.add('active');
    }
  }

  // --- STEP 1: REGISTRATION ---
  const registerForm = document.getElementById('registerForm');
  const submitBtn = document.getElementById('submitBtn');
  const spinner = document.getElementById('spinner');
  const btnText = document.getElementById('btnText');

  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const firstName = document.getElementById('firstName').value.trim();
    const lastName = document.getElementById('lastName').value.trim();
    const email = document.getElementById('email').value.trim();
    const phone = document.getElementById('phone').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!firstName || !lastName || !email || !phone || !password || !confirmPassword) {
      return showAlert('Please fill in all fields.');
    }

    if (password !== confirmPassword) {
      return showAlert('Password and Confirm Password do not match.');
    }

    submitBtn.disabled = true;
    spinner.style.display = 'inline-block';
    btnText.textContent = 'Creating Account...';

    try {
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firstName, lastName, email, phone, password, confirmPassword })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        submitBtn.disabled = false;
        spinner.style.display = 'none';
        btnText.textContent = 'Create Account';
        return showAlert(data.message || 'Registration failed.');
      }

      // Store in memory
      window.registrationSession.userId = data.userId;
      window.registrationSession.challengeId = data.challengeId;

      showStep('step2-email-otp');
      showAlert('Registration created. Please verify your email.', 'success');

    } catch (error) {
      console.error('Registration fetch error:', error);
      submitBtn.disabled = false;
      spinner.style.display = 'none';
      btnText.textContent = 'Create Account';
      showAlert('Unable to reach authentication server.');
    }
  });

  // --- STEP 2: EMAIL OTP ---
  const emailOtpInput = document.getElementById('emailOtpInput');
  const verifyEmailOtpBtn = document.getElementById('verifyEmailOtpBtn');
  const resendEmailOtpBtn = document.getElementById('resendEmailOtpBtn');
  const emailSpinner = document.getElementById('emailSpinner');

  verifyEmailOtpBtn.addEventListener('click', async () => {
    hideAlert();
    const otp = emailOtpInput.value.trim();
    if (!otp || otp.length !== 6) {
      return showAlert('Please enter a 6-digit OTP code.');
    }

    verifyEmailOtpBtn.disabled = true;
    emailSpinner.style.display = 'inline-block';

    try {
      const response = await fetch('/api/verify-email-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: window.registrationSession.challengeId,
          otp: otp
        })
      });

      const data = await response.json();
      verifyEmailOtpBtn.disabled = false;
      emailSpinner.style.display = 'none';

      if (!response.ok || !data.success) {
        if (data.code === 'INVALID_OTP' && data.attemptsRemaining !== undefined) {
          return showAlert(`Incorrect OTP.\nAttempts remaining: ${data.attemptsRemaining}`);
        }
        return showAlert(data.message || 'OTP Verification failed.');
      }

      // Email verified! Now generate SMS OTP and move to Step 3
      triggerSendSmsOtp();

    } catch (error) {
      console.error('Email OTP verify error:', error);
      verifyEmailOtpBtn.disabled = false;
      emailSpinner.style.display = 'none';
      showAlert('Error communicating with server.');
    }
  });

  resendEmailOtpBtn.addEventListener('click', async () => {
    hideAlert();
    resendEmailOtpBtn.disabled = true;

    try {
      const response = await fetch('/api/send-email-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: window.registrationSession.userId })
      });

      const data = await response.json();
      resendEmailOtpBtn.disabled = false;

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to resend OTP.');
      }

      window.registrationSession.challengeId = data.challengeId;
      emailOtpInput.value = '';
      showAlert('New verification code sent to your email.', 'success');

    } catch (error) {
      console.error('Resend Email OTP error:', error);
      resendEmailOtpBtn.disabled = false;
      showAlert('Error communicating with server.');
    }
  });

  // Helper to trigger SMS OTP creation after email verification
  async function triggerSendSmsOtp() {
    try {
      const response = await fetch('/api/send-sms-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: window.registrationSession.userId })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to generate SMS OTP.');
      }

      window.registrationSession.challengeId = data.challengeId;
      showStep('step3-sms-otp');
      showAlert('Email verified! SMS verification code sent to your phone.', 'success');

    } catch (error) {
      console.error('Send SMS OTP error:', error);
      showAlert('Failed to initiate SMS OTP verification.');
    }
  }

  // --- STEP 3: SMS OTP ---
  const smsOtpInput = document.getElementById('smsOtpInput');
  const verifySmsOtpBtn = document.getElementById('verifySmsOtpBtn');
  const resendSmsOtpBtn = document.getElementById('resendSmsOtpBtn');
  const smsSpinner = document.getElementById('smsSpinner');

  verifySmsOtpBtn.addEventListener('click', async () => {
    hideAlert();
    const otp = smsOtpInput.value.trim();
    if (!otp || otp.length !== 6) {
      return showAlert('Please enter a 6-digit OTP code.');
    }

    verifySmsOtpBtn.disabled = true;
    smsSpinner.style.display = 'inline-block';

    try {
      const response = await fetch('/api/verify-sms-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: window.registrationSession.challengeId,
          otp: otp
        })
      });

      const data = await response.json();
      verifySmsOtpBtn.disabled = false;
      smsSpinner.style.display = 'none';

      if (!response.ok || !data.success) {
        if (data.code === 'INVALID_OTP' && data.attemptsRemaining !== undefined) {
          return showAlert(`Incorrect OTP.\nAttempts remaining: ${data.attemptsRemaining}`);
        }
        return showAlert(data.message || 'SMS OTP Verification failed.');
      }

      // SMS Verified & MFA Enabled! Show Step 4 (MFA Complete Screen)
      showStep('step4-mfa-complete');

    } catch (error) {
      console.error('SMS OTP verify error:', error);
      verifySmsOtpBtn.disabled = false;
      smsSpinner.style.display = 'none';
      showAlert('Error communicating with server.');
    }
  });

  resendSmsOtpBtn.addEventListener('click', async () => {
    hideAlert();
    resendSmsOtpBtn.disabled = true;

    try {
      const response = await fetch('/api/send-sms-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: window.registrationSession.userId })
      });

      const data = await response.json();
      resendSmsOtpBtn.disabled = false;

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to resend SMS OTP.');
      }

      window.registrationSession.challengeId = data.challengeId;
      smsOtpInput.value = '';
      showAlert('New verification code sent to your phone.', 'success');

    } catch (error) {
      console.error('Resend SMS OTP error:', error);
      resendSmsOtpBtn.disabled = false;
      showAlert('Error communicating with server.');
    }
  });

  // --- STEP 4 -> STEP 5 TRANSITION ---
  const continueMfaBtn = document.getElementById('continueMfaBtn');
  continueMfaBtn.addEventListener('click', () => {
    showStep('step5-final-success');
  });

});
