document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');
  const auditLogsContainer = document.getElementById('auditLogsContainer');

  function showAlert(message, type = 'error') {
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
  }

  function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, 
      tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
      }[tag] || tag)
    );
  }

  async function loadAuditLogs() {
    try {
      const response = await fetch('/api/audit-logs', { method: 'GET' });
      const data = await response.json();

      if (!response.ok || !data.success) {
        window.location.href = 'login.html';
        return;
      }

      renderAuditLogs(data.logs || []);
    } catch (error) {
      console.error('Error loading audit logs:', error);
      showAlert('Unable to fetch security activity logs.');
    }
  }

  function renderAuditLogs(logs) {
    if (logs.length === 0) {
      auditLogsContainer.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 20px;">No security event logs found.</p>';
      return;
    }

    auditLogsContainer.innerHTML = logs.map(log => {
      const timestamp = new Date(log.created_at).toLocaleString();
      let tagClass = 'tag-info';

      if (log.event_type.includes('SUCCESS') || log.event_type.includes('VERIFIED')) {
        tagClass = 'tag-success';
      } else if (log.event_type.includes('FAILED') || log.event_type.includes('WEAK')) {
        tagClass = 'tag-danger';
      } else if (log.event_type.includes('REVOKED') || log.event_type.includes('RESET')) {
        tagClass = 'tag-warning';
      }

      return `
        <div class="audit-item">
          <div>
            <div style="font-size: 0.9rem; font-weight: 600; color: var(--text-main); margin-bottom: 4px;">
              ${escapeHTML(log.event_type)}
            </div>
            <div style="font-size: 0.82rem; color: var(--text-muted);">
              ${escapeHTML(log.event_details || 'Security event recorded.')}
            </div>
            <div style="font-size: 0.75rem; color: rgba(255,255,255,0.4); margin-top: 4px;">
              ${escapeHTML(timestamp)}
            </div>
          </div>
          <div>
            <span class="event-tag ${tagClass}">${escapeHTML(log.event_type.split('_')[0])}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  loadAuditLogs();
});
