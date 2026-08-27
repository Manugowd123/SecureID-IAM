document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');

  window.resetSession = {
    challengeId: null,
    resetToken: null
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

  // --- STEP 1: REQUEST OTP ---
  const forgotForm = document.getElementById('forgotForm');
  const forgotBtn = document.getElementById('forgotBtn');
  const forgotSpinner = document.getElementById('forgotSpinner');
  const forgotBtnText = document.getElementById('forgotBtnText');

  forgotForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const email = document.getElementById('resetEmail').value.trim();

    if (!email) {
      return showAlert('Please enter your email address.');
    }

    forgotBtn.disabled = true;
    forgotSpinner.style.display = 'inline-block';
    forgotBtnText.textContent = 'Sending...';

    try {
      const response = await fetch('/api/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const data = await response.json();
      forgotBtn.disabled = false;
      forgotSpinner.style.display = 'none';
      forgotBtnText.textContent = 'Send Reset Code';

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to generate password reset request.');
      }

      window.resetSession.challengeId = data.challengeId;
      showStep('step2-reset');
      showAlert('Password reset code sent to your email. Enter the OTP and your new password.', 'success');

    } catch (error) {
      console.error('Forgot password error:', error);
      forgotBtn.disabled = false;
      forgotSpinner.style.display = 'none';
      forgotBtnText.textContent = 'Send Reset Code';
      showAlert('Unable to connect to server.');
    }
  });

  // --- STEP 2: VERIFY OTP & RESET PASSWORD ---
  const resetForm = document.getElementById('resetForm');
  const resetBtn = document.getElementById('resetBtn');
  const resetSpinner = document.getElementById('resetSpinner');
  const resetBtnText = document.getElementById('resetBtnText');

  resetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const otp = document.getElementById('resetOtpInput').value.trim();
    const newPassword = document.getElementById('newPassword').value;
    const confirmNewPassword = document.getElementById('confirmNewPassword').value;

    if (!otp || otp.length !== 6) {
      return showAlert('Please enter a 6-digit OTP code.');
    }

    if (!newPassword || !confirmNewPassword) {
      return showAlert('Please enter and confirm your new password.');
    }

    if (newPassword !== confirmNewPassword) {
      return showAlert('Passwords do not match.');
    }

    resetBtn.disabled = true;
    resetSpinner.style.display = 'inline-block';
    resetBtnText.textContent = 'Verifying & Resetting...';

    try {
      // 1. Verify OTP first to get secure single-use resetToken
      let resetToken = window.resetSession.resetToken;

      if (!resetToken) {
        const verifyRes = await fetch('/api/verify-reset-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            challengeId: window.resetSession.challengeId,
            otp: otp
          })
        });

        const verifyData = await verifyRes.json();
        if (!verifyRes.ok || !verifyData.success) {
          resetBtn.disabled = false;
          resetSpinner.style.display = 'none';
          resetBtnText.textContent = 'Reset Password';
          return showAlert(verifyData.message || 'Invalid or expired OTP.');
        }

        resetToken = verifyData.resetToken;
        window.resetSession.resetToken = resetToken;
      }

      // 2. Submit new password with single-use resetToken
      const response = await fetch('/api/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resetToken: resetToken,
          newPassword: newPassword,
          confirmPassword: confirmNewPassword
        })
      });

      const data = await response.json();
      resetBtn.disabled = false;
      resetSpinner.style.display = 'none';
      resetBtnText.textContent = 'Reset Password';

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to reset password.');
      }

      showStep('step3-success');

    } catch (error) {
      console.error('Reset password error:', error);
      resetBtn.disabled = false;
      resetSpinner.style.display = 'none';
      resetBtnText.textContent = 'Reset Password';
      showAlert('Error communicating with server.');
    }
  });
});
