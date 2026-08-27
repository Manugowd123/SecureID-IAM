document.addEventListener('DOMContentLoaded', () => {
  const alertBox = document.getElementById('alertBox');
  const clientNameDisplay = document.getElementById('clientNameDisplay');
  const allowBtn = document.getElementById('allowBtn');
  const cancelBtn = document.getElementById('cancelBtn');

  function showAlert(message, type = 'error') {
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
  }

  const urlParams = new URLSearchParams(window.location.search);
  const clientId = urlParams.get('client_id');
  const redirectUri = urlParams.get('redirect_uri');
  const responseType = urlParams.get('response_type') || 'code';
  const scope = urlParams.get('scope') || 'openid profile email';

  if (!clientId || !redirectUri) {
    showAlert('Missing client_id or redirect_uri parameters in authorization request.');
    allowBtn.disabled = true;
    return;
  }

  clientNameDisplay.textContent = clientId;

  allowBtn.addEventListener('click', async () => {
    try {
      allowBtn.disabled = true;
      allowBtn.textContent = 'Authorizing...';

      const response = await fetch(`/api/oauth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=${encodeURIComponent(responseType)}&scope=${encodeURIComponent(scope)}`, {
        method: 'GET'
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        allowBtn.disabled = false;
        allowBtn.textContent = 'Allow & Authorize';
        return showAlert(data.message || 'Authorization failed.');
      }

      showAlert('Authorized! Redirecting to client application...', 'success');
      setTimeout(() => {
        window.location.href = data.redirectUri;
      }, 1000);

    } catch (error) {
      console.error('OAuth authorization error:', error);
      allowBtn.disabled = false;
      allowBtn.textContent = 'Allow & Authorize';
      showAlert('Error during authorization processing.');
    }
  });

  cancelBtn.addEventListener('click', () => {
    window.location.href = 'login.html';
  });
});
