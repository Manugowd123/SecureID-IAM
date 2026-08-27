document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');

  // In-memory session tracking for active login journey
  window.loginSession = {
    userId: null,
    challengeId: null,
    rememberMe: false
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

  function renderDashboard(user) {
    if (user) {
      document.getElementById('userFullName').textContent = `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'User';
      document.getElementById('userEmail').textContent = user.email || '-';
      document.getElementById('userPhone').textContent = user.phone || '-';
    }
    showStep('step3-dashboard');
    showAlert('Welcome back! Login complete.', 'success');
  }

  // --- AUTO SESSION CHECK ON PAGE LOAD USING HttpOnly COOKIE ---
  fetch('/api/me', {
    method: 'GET'
  })
  .then(res => res.json())
  .then(data => {
    if (data.success && data.user) {
      renderDashboard(data.user);
    }
  })
  .catch(err => {
    console.error('Session auto-check error:', err);
  });

  // --- STEP 1: LOGIN FORM SUBMIT ---
  const loginForm = document.getElementById('loginForm');
  const loginBtn = document.getElementById('loginBtn');
  const loginSpinner = document.getElementById('loginSpinner');
  const loginBtnText = document.getElementById('loginBtnText');

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe').checked;

    if (!email || !password) {
      return showAlert('Please enter both email and password.');
    }

    loginBtn.disabled = true;
    loginSpinner.style.display = 'inline-block';
    loginBtnText.textContent = 'Signing in...';

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, rememberMe })
      });

      const data = await response.json();
      loginBtn.disabled = false;
      loginSpinner.style.display = 'none';
      loginBtnText.textContent = 'Sign In';

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Login failed. Please check your credentials.');
      }

      window.loginSession.userId = data.userId;
      window.loginSession.rememberMe = rememberMe;

      if (data.mfaRequired) {
        window.loginSession.challengeId = data.challengeId;
        showStep('step2-login-mfa');
        showAlert('Password verified. Enter the 6-digit OTP code sent to your phone.', 'success');
      } else {
        // Direct login success (No MFA) -> HttpOnly cookie set automatically by server
        renderDashboard(data.user);
      }

    } catch (error) {
      console.error('Login error:', error);
      loginBtn.disabled = false;
      loginSpinner.style.display = 'none';
      loginBtnText.textContent = 'Sign In';
      showAlert('Unable to connect to authentication server.');
    }
  });

  // --- STEP 2: MFA VERIFICATION ---
  const loginOtpInput = document.getElementById('loginOtpInput');
  const verifyLoginOtpBtn = document.getElementById('verifyLoginOtpBtn');
  const resendLoginOtpBtn = document.getElementById('resendLoginOtpBtn');
  const mfaSpinner = document.getElementById('mfaSpinner');

  verifyLoginOtpBtn.addEventListener('click', async () => {
    hideAlert();
    const otp = loginOtpInput.value.trim();
    if (!otp || otp.length !== 6) {
      return showAlert('Please enter a 6-digit OTP code.');
    }

    verifyLoginOtpBtn.disabled = true;
    mfaSpinner.style.display = 'inline-block';

    try {
      const response = await fetch('/api/verify-login-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: window.loginSession.challengeId,
          otp: otp,
          rememberMe: window.loginSession.rememberMe
        })
      });

      const data = await response.json();
      verifyLoginOtpBtn.disabled = false;
      mfaSpinner.style.display = 'none';

      if (!response.ok || !data.success) {
        if (data.code === 'INVALID_OTP' && data.attemptsRemaining !== undefined) {
          return showAlert(`Incorrect OTP.\nAttempts remaining: ${data.attemptsRemaining}`);
        }
        return showAlert(data.message || 'OTP verification failed.');
      }

      // MFA Verified -> HttpOnly cookie set automatically by server
      renderDashboard(data.user);

    } catch (error) {
      console.error('Verify login OTP error:', error);
      verifyLoginOtpBtn.disabled = false;
      mfaSpinner.style.display = 'none';
      showAlert('Error communicating with server.');
    }
  });

  resendLoginOtpBtn.addEventListener('click', async () => {
    hideAlert();
    resendLoginOtpBtn.disabled = true;

    try {
      const response = await fetch('/api/send-login-sms-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: window.loginSession.userId })
      });

      const data = await response.json();
      resendLoginOtpBtn.disabled = false;

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to resend SMS OTP.');
      }

      window.loginSession.challengeId = data.challengeId;
      loginOtpInput.value = '';
      showAlert('New verification code sent to your phone.', 'success');

    } catch (error) {
      console.error('Resend login SMS OTP error:', error);
      resendLoginOtpBtn.disabled = false;
      showAlert('Error communicating with server.');
    }
  });

  // --- STEP 3: LOGOUT HANDLER ---
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      hideAlert();
      logoutBtn.disabled = true;

      try {
        const response = await fetch('/api/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();
        logoutBtn.disabled = false;

        if (!response.ok || !data.success) {
          console.warn('[LOGOUT WARNING]', data.message);
        }
      } catch (err) {
        console.error('[LOGOUT ERROR] Logout API call failed:', err);
        logoutBtn.disabled = false;
      }

      // Reset in-memory session after request completes
      window.loginSession = { userId: null, challengeId: null };

      showStep('step1-login');
      showAlert('You have signed out.', 'success');
    });
  }
});
