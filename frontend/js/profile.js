document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');

  function showAlert(message, type = 'error') {
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
  }

  function hideAlert() {
    alertBox.style.display = 'none';
    alertBox.textContent = '';
  }

  // --- FETCH INITIAL USER PROFILE ---
  fetch('/api/me', { method: 'GET' })
    .then(res => res.json())
    .then(data => {
      if (!data.success || !data.user) {
        window.location.href = 'login.html';
        return;
      }
      populateProfileForm(data.user);
    })
    .catch(err => {
      console.error('Error fetching profile:', err);
      showAlert('Unable to load profile data.');
    });

  function populateProfileForm(user) {
    document.getElementById('firstName').value = user.firstName || '';
    document.getElementById('lastName').value = user.lastName || '';
    document.getElementById('emailDisplay').value = user.email || '';
    document.getElementById('phone').value = user.phone || '';

    const mfaBadge = document.getElementById('mfaBadge');
    if (user.mfaEnabled) {
      mfaBadge.textContent = '🔒 SMS MFA Active';
      mfaBadge.style.background = 'rgba(37, 99, 235, 0.15)';
      mfaBadge.style.color = '#60a5fa';
    } else {
      mfaBadge.textContent = '⚠️ MFA Inactive (Verification Pending)';
      mfaBadge.style.background = 'rgba(234, 179, 8, 0.15)';
      mfaBadge.style.color = '#eab308';
    }
  }

  // --- SAVE PROFILE CHANGES ---
  const profileForm = document.getElementById('profileForm');
  const updateProfileBtn = document.getElementById('updateProfileBtn');
  const profileSpinner = document.getElementById('profileSpinner');
  const profileBtnText = document.getElementById('profileBtnText');

  profileForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const firstName = document.getElementById('firstName').value.trim();
    const lastName = document.getElementById('lastName').value.trim();
    const phone = document.getElementById('phone').value.trim();

    if (!firstName || !lastName || !phone) {
      return showAlert('All profile fields are required.');
    }

    updateProfileBtn.disabled = true;
    profileSpinner.style.display = 'inline-block';
    profileBtnText.textContent = 'Saving...';

    try {
      const response = await fetch('/api/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firstName, lastName, phone })
      });

      const data = await response.json();
      updateProfileBtn.disabled = false;
      profileSpinner.style.display = 'none';
      profileBtnText.textContent = 'Save Profile Changes';

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to update profile.');
      }

      populateProfileForm(data.user);
      showAlert(data.message || 'Profile updated successfully.', 'success');

    } catch (error) {
      console.error('Update profile error:', error);
      updateProfileBtn.disabled = false;
      profileSpinner.style.display = 'none';
      profileBtnText.textContent = 'Save Profile Changes';
      showAlert('Error communicating with server.');
    }
  });

  // --- CHANGE PASSWORD ---
  const changePasswordForm = document.getElementById('changePasswordForm');
  const changePasswordBtn = document.getElementById('changePasswordBtn');
  const passwordSpinner = document.getElementById('passwordSpinner');
  const passwordBtnText = document.getElementById('passwordBtnText');

  changePasswordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmNewPassword = document.getElementById('confirmNewPassword').value;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
      return showAlert('Please fill in all password fields.');
    }

    if (newPassword !== confirmNewPassword) {
      return showAlert('New passwords do not match.');
    }

    changePasswordBtn.disabled = true;
    passwordSpinner.style.display = 'inline-block';
    passwordBtnText.textContent = 'Updating...';

    try {
      const response = await fetch('/api/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword, confirmPassword })
      });

      const data = await response.json();
      changePasswordBtn.disabled = false;
      passwordSpinner.style.display = 'none';
      passwordBtnText.textContent = 'Update Password';

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to change password.');
      }

      changePasswordForm.reset();
      showAlert('Password updated successfully.', 'success');

    } catch (error) {
      console.error('Change password error:', error);
      changePasswordBtn.disabled = false;
      passwordSpinner.style.display = 'none';
      passwordBtnText.textContent = 'Update Password';
      showAlert('Error communicating with server.');
    }
  });
});
