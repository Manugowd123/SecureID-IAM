document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');
  const adminTableContainer = document.getElementById('adminTableContainer');

  function showAlert(message, type = 'error') {
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
  }

  function hideAlert() {
    alertBox.style.display = 'none';
    alertBox.textContent = '';
  }

  function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>'"]/g, 
      tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
      }[tag] || tag)
    );
  }

  async function loadAdminUsers() {
    try {
      const response = await fetch('/api/admin/users', { method: 'GET' });
      const data = await response.json();

      if (response.status === 403) {
        showAlert('Access Denied. Administrator privileges required.');
        adminTableContainer.innerHTML = '<p style="text-align: center; color: #ef4444; padding: 20px;">Access Denied. Administrator role required.</p>';
        return;
      }

      if (!response.ok || !data.success) {
        window.location.href = 'login.html';
        return;
      }

      renderUserDirectory(data.users || []);
    } catch (error) {
      console.error('Error loading admin users:', error);
      showAlert('Unable to fetch user directory.');
    }
  }

  function renderUserDirectory(users) {
    if (users.length === 0) {
      adminTableContainer.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 20px;">No registered users found.</p>';
      return;
    }

    adminTableContainer.innerHTML = `
      <table class="user-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>MFA</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(u => `
            <tr>
              <td>${escapeHTML(u.id)}</td>
              <td style="font-weight: 600;">${escapeHTML(u.firstName)} ${escapeHTML(u.lastName)}</td>
              <td>${escapeHTML(u.email)}</td>
              <td><span class="role-badge ${u.role === 'admin' ? 'role-admin' : 'role-user'}">${escapeHTML(u.role.toUpperCase())}</span></td>
              <td>${u.mfaEnabled ? '🔒 Active' : 'Off'}</td>
              <td>${u.isLocked ? '<span class="status-locked">Locked</span>' : '<span class="status-active">Active</span>'}</td>
              <td>
                <button type="button" class="btn-secondary" onclick="toggleLock(${u.id}, ${!u.isLocked})" style="font-size: 0.75rem; padding: 4px 8px;">
                  ${u.isLocked ? 'Unlock' : 'Lock'}
                </button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  window.toggleLock = async (userId, shouldLock) => {
    hideAlert();
    try {
      const response = await fetch(`/api/admin/users/${userId}/lock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lock: shouldLock })
      });
      const data = await response.json();

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to update lock status.');
      }

      showAlert(data.message || 'User lock status updated.', 'success');
      loadAdminUsers();
    } catch (error) {
      console.error('Error toggling lock:', error);
      showAlert('Error updating user lock status.');
    }
  };

  loadAdminUsers();
});
