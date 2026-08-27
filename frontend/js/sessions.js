document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');
  const sessionsListContainer = document.getElementById('sessionsListContainer');
  const revokeOthersBtn = document.getElementById('revokeOthersBtn');

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

  async function loadSessions() {
    try {
      const response = await fetch('/api/sessions', { method: 'GET' });
      const data = await response.json();

      if (!response.ok || !data.success) {
        window.location.href = 'login.html';
        return;
      }

      renderSessions(data.sessions || []);
    } catch (error) {
      console.error('Error loading sessions:', error);
      showAlert('Unable to fetch active sessions.');
    }
  }

  function renderSessions(sessions) {
    if (sessions.length === 0) {
      sessionsListContainer.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 20px;">No active sessions found.</p>';
      return;
    }

    sessionsListContainer.innerHTML = sessions.map(session => {
      const createdDate = new Date(session.createdAt).toLocaleString();
      const expiresDate = new Date(session.expiresAt).toLocaleString();

      return `
        <div class="session-item ${session.isCurrentSession ? 'session-current' : ''}">
          <div>
            <div style="font-size: 0.9rem; font-weight: 600; color: var(--text-main);">
              Session ${escapeHTML(session.sessionIdMasked)}
              ${session.isCurrentSession ? '<span class="badge-current">Current Device</span>' : ''}
            </div>
            <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 4px;">
              Created: ${escapeHTML(createdDate)} | Expires: ${escapeHTML(expiresDate)}
            </div>
          </div>
          <div>
            ${session.isCurrentSession 
              ? `<button type="button" class="btn-secondary" onclick="revokeSingleSession('${escapeHTML(session.sessionId)}')" style="font-size: 0.78rem; padding: 6px 10px;">Sign Out</button>`
              : `<button type="button" class="btn-secondary" onclick="revokeSingleSession('${escapeHTML(session.sessionId)}')" style="font-size: 0.78rem; padding: 6px 10px; border-color: rgba(239, 68, 68, 0.4); color: #ef4444;">Revoke</button>`
            }
          </div>
        </div>
      `;
    }).join('');
  }

  window.revokeSingleSession = async (sessionId) => {
    hideAlert();
    try {
      const response = await fetch('/api/sessions/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetSessionId: sessionId })
      });
      const data = await response.json();

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to revoke session.');
      }

      showAlert('Session revoked successfully.', 'success');
      loadSessions();
    } catch (error) {
      console.error('Error revoking session:', error);
      showAlert('Error revoking session.');
    }
  };

  revokeOthersBtn.addEventListener('click', async () => {
    hideAlert();
    if (!confirm('Are you sure you want to sign out of all other devices?')) return;

    try {
      const response = await fetch('/api/sessions/revoke-others', { method: 'POST' });
      const data = await response.json();

      if (!response.ok || !data.success) {
        return showAlert(data.message || 'Failed to revoke other sessions.');
      }

      showAlert(data.message || 'All other active sessions revoked.', 'success');
      loadSessions();
    } catch (error) {
      console.error('Error revoking other sessions:', error);
      showAlert('Error revoking other sessions.');
    }
  });

  loadSessions();
});
